#include "IOCPManager.h"
#include "IOContext.h"
#include "../offlineManager/ManageOffline.h"
#include "../session/SessionManager.h"
#include "../session/Session.h"
#include "../chat/MessageRouter.h"
#include "../utils/Logger.h"
#include <ws2tcpip.h>
#include <cstring>
#include <memory>
#include <unordered_map>
#include "./protocol/Packet.h"
#include "./pool/PacketPool.h"
#include "./pool/SessionPool.h"
#include "./pool/IOContextPool.h"
#include "./datastructure/circularBuffer.h"
IOContextPool pio;
struct ConnectionBuffer
{
    CircularBuffer buffer;
    std::mutex bufMtx;                    // per-buffer lock
    std::atomic<bool> disconnected{false}; // poison flag
   
};

std::unordered_map<SOCKET, std::shared_ptr<ConnectionBuffer>> socketBuffers;
std::mutex IOCPManager::socketBuffersMutex;

IOCPManager::IOCPManager()
    : iocpHandle(NULL), listenSocket(INVALID_SOCKET), sessionManager(nullptr), messageRouter(nullptr), numWorkerThreads(0)
{
}

IOCPManager::~IOCPManager()
{
    shutdown();
}

bool IOCPManager::initialize(int port, SessionManager *sm, MessageRouter *mr, ManageOffline *mf)
{
    sessionManager = sm;
    offlineManager = mf;
    messageRouter = mr;
    WSADATA wsa;

    // int res = WSAStartup(MAKEWORD(2, 2), &wsa);
    // if (res != 0)
    // {
    //     std::cout << " conection failed\n";
    //     return false;
    // }
    // Create listen socket
    listenSocket = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (listenSocket == INVALID_SOCKET)
    {
        Logger::error("Failed to create listen socket, error: " + std::to_string(WSAGetLastError()));
        return false;
    }

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<u_short>(port));
    address.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
    {
        Logger::error("Bind failed, error: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket);
        return false;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        Logger::error("Listen failed, error: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket);
        return false;
    }

    // Create IOCP handle
    iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (iocpHandle == NULL)
    {
        Logger::error("Failed to create IO completion port");
        closesocket(listenSocket);
        return false;
    }

    // Determine number of worker threads (2x CPU cores)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    numWorkerThreads = static_cast<int>(sysInfo.dwNumberOfProcessors * 2);
    if (numWorkerThreads < 2)
        numWorkerThreads = 2;

    // Launch worker threads
    for (int i = 0; i < numWorkerThreads; i++)
    {
        workerThreads.emplace_back(&IOCPManager::workerThread, this);
    }

    Logger::info("IOCP server initialized on port " + std::to_string(port) +
                 " with " + std::to_string(numWorkerThreads) + " worker threads");
    return true;
}
// primary thread wait for connection
void IOCPManager::acceptLoop()
{
    Logger::info("Accept loop started, waiting for connections...");

    while (true)
    {
        sockaddr_in clientAddress;
        int addrLen = sizeof(clientAddress);

        SOCKET clientSocket = WSAAccept(listenSocket, (sockaddr *)&clientAddress, &addrLen, NULL, 0);
        if (clientSocket == INVALID_SOCKET)
        {
            int err = WSAGetLastError();
            if (err == WSAEINTR || err == WSAENOTSOCK)
            {
                Logger::info("Accept loop terminated");
                break; // Server is shutting down
            }
            Logger::warn("WSAAccept failed, error: " + std::to_string(err));
            continue;
        }

        // Associate client socket with IOCP
        HANDLE result = CreateIoCompletionPort((HANDLE)clientSocket, iocpHandle, (ULONG_PTR)clientSocket, 0);
        if (result == NULL)
        {
            Logger::warn("Failed to associate client socket with IOCP");
            closesocket(clientSocket);
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(disconnectMtx);
            disconnectedSockets.erase(clientSocket);
        }

        // Session userId will be set when client sends LOGIN packet
        {
            std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
            socketBuffers[clientSocket] = std::make_shared<ConnectionBuffer>();
        }

        Logger::info("New connection accepted (socket: " + std::to_string(clientSocket) + ")");

        // Post initial receive
        if (!postRecv(clientSocket))
        {
            Logger::warn("Failed to post initial recv on new connection");
            handleDisconnect(clientSocket);
        }
    }
}

void IOCPManager::workerThread()
{
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED lpOverlapped;

    while (true)
    {
        BOOL success = GetQueuedCompletionStatus(
            iocpHandle, &bytesTransferred, &completionKey, &lpOverlapped, INFINITE);

        // Check for shutdown signal (completionKey == 0 and bytesTransferred == 0)
        if (completionKey == 0 && bytesTransferred == 0 && lpOverlapped == nullptr)
        {
            break; // Shutdown signal
        }

        SOCKET clientSocket = (SOCKET)completionKey;
        PER_IO_OPERATION_DATA *pData = (PER_IO_OPERATION_DATA *)lpOverlapped;
        // socket closed during receving
        if (!success || (bytesTransferred == 0 && pData->operationType != 2))
        {
            // Connection closed or error
            //  If this was a pending send, recover the in-flight packet, note no need to recover packet as it is already habdled means it is not thrown from the queue
            if (pData->operationType == 0 && pData->packet)
            {
                pData->packet->isSending = false;
                pData->packet->isSentFail = true;
                if (!pData->packet->bypassQueue)
                {
                    std::string recvId = sessionManager->getUserIdBySocket(clientSocket);
                    offlineManager->ManageCompletePacket(pData->packet, recvId);
                }
                else
                {
                    PacketPool::Instance().returnPacket(pData->packet);
                }
            }
            pio.returnIOPdata(pData);
            handleDisconnect(clientSocket);
            continue;
        }

        if (pData->operationType == 2)
        { // zero-byte recv notification
            pio.returnIOPdata(pData);

            bool shouldDisconnect = false;
            std::vector<Packet *> localQueue;
            localQueue.reserve(8);

            // Step 1: Short global lock — just grab a shared_ptr copy
            std::shared_ptr<ConnectionBuffer> connBuf;
            {
                std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
                auto it = socketBuffers.find(clientSocket);
                if (it != socketBuffers.end())
                {
                    connBuf = it->second; // refcount++ keeps buffer alive
                }
            }
            // Global lock released — other sockets are unblocked

            if (!connBuf)
            {
                shouldDisconnect = true;
            }
            else
            {
                // Step 2: Per-buffer lock — only blocks THIS socket's operations
                std::lock_guard<std::mutex> bufLock(connBuf->bufMtx);

                if (connBuf->disconnected.load(std::memory_order_acquire))
                {
                    shouldDisconnect = true;
                }
                else
                {
                    auto &recvBuffer = connBuf->buffer;

                    WSABUF bufs[2];
                    int bufferCount = recvBuffer.getWriteBuffers(bufs);

                    if (bufferCount > 0)
                    {
                        DWORD bytesRead = 0, flags = 0;

                        // Synchronous WSARecv — 0-byte notification guarantees data is available
                        int result = WSARecv(clientSocket, bufs, bufferCount, &bytesRead, &flags, NULL, NULL);

                        if (result != SOCKET_ERROR && bytesRead > 0)
                        {
                            recvBuffer.commitWrite(bytesRead);

                            while (true)
                            {
                                if (recvBuffer.size() < HEADER_SIZE) break;

                                PacketHeader hdr;
                                recvBuffer.copy(reinterpret_cast<uint8_t *>(&hdr), sizeof(PacketHeader));

                                if (hdr.magic != START_BYTE || hdr.version != CURRENT_VERSION)
                                {
                                    Logger::warn("Invalid magic byte");
                                    shouldDisconnect = true;
                                    break;
                                }

                                uint32_t payloadSize = ntohl(hdr.payload_length);
                                uint32_t packetSize = HEADER_SIZE + payloadSize;

                                if (packetSize < HEADER_SIZE)
                                {
                                    Logger::warn("Invalid packet size");
                                    shouldDisconnect = true;
                                    break;
                                }

                                if (packetSize > sizeof(Packet::data))
                                {
                                    Logger::warn("Packet too large");
                                    shouldDisconnect = true;
                                    break;
                                }

                                if (recvBuffer.size() < packetSize)
                                {
                                    break; // Incomplete packet, wait for more data
                                }

                                Packet *p = PacketPool::Instance().borrowPacket();
                                if (p == nullptr) break;

                                recvBuffer.consume(reinterpret_cast<uint8_t *>(p->data), packetSize);
                                p->in = p->data + packetSize;

                                localQueue.push_back(p);
                            }
                        }
                        else if (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
                        {
                            shouldDisconnect = true;
                        }
                        else if (result == 0 && bytesRead == 0)
                        {
                            // Graceful close
                            shouldDisconnect = true;
                        }
                    }
                }
            } // Per-buffer lock released here

            // Dispatch packets completely lock-free
            if (!localQueue.empty())
            {
                Session *s = sessionManager->findBySocket(clientSocket);
                std::string tempId = std::to_string(static_cast<uintptr_t>(clientSocket)) + "id";

                if (!s)
                {
                    s = SessionPool::Instance().borrowSession(clientSocket);
                    if (s)
                    {
                        s->iocp = this;
                        s->socket = clientSocket;
                        s->userId = tempId;
                        sessionManager->addSession(tempId, s);
                    }
                }

                if (!s)
                {
                    for (Packet *p : localQueue) PacketPool::Instance().returnPacket(p);
                    Logger::warn("Failed to get or create session for socket");
                    shouldDisconnect = true;
                }
                else
                {
                    for (Packet *p : localQueue)
                    {
                        bool parsed = p->parseHeader();
                        bool parsedData = p->parseData();
                        if (!parsed||!parsedData)
                        {
                            Logger::info("failed to parse the header\n");
                            PacketPool::Instance().returnPacket(p);
                            continue;
                        }

                        bool handled = messageRouter->handlePacket(p, s);
                        if (!handled)
                        {
                            PacketPool::Instance().returnPacket(p);
                            Logger::info("iocpmanager.cpp : packet not handled");
                        }
                    }
                }
            }

            // All handleDisconnect calls are OUTSIDE both locks — no deadlock possible
            if (shouldDisconnect)
            {
                handleDisconnect(clientSocket);
            }
            else
            {
                if (!postRecv(clientSocket)) {
    handleDisconnect(clientSocket);
}
            }
        }
        else if (pData->operationType == 0)
        { // send
            Packet *sentPacket = pData->packet;

          
            // sentPacket->isSentFail = true;

            if (sentPacket)
            { 
              
                pData->bytesSent += bytesTransferred;

                if (pData->bytesSent < pData->totalToSend)
                {
                    // Partial send: re-post WSASend for remaining bytes
                    int remaining = pData->totalToSend - pData->bytesSent;
                    pData->buffer.buf = reinterpret_cast<char *>(pData->packet->data) + pData->bytesSent;
                    pData->buffer.len = remaining;

                    DWORD sent = 0;
                    ZeroMemory(&pData->overlapped, sizeof(OVERLAPPED));
                    int result = WSASend(clientSocket, &pData->buffer, 1, &sent, 0,
                                         &pData->overlapped, NULL);
                    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
                    {
                        Logger::warn("WSASend (partial resend) failed on socket " +
                                     std::to_string(clientSocket));
                        sentPacket->isSending = false;
                        sentPacket->isSentFail = true;
                        // Save receiverId before returning pData — after returnIOPdata,
                        // pData (and its pointers) may be reused by another thread.
                        std::string recvId = sessionManager->getUserIdBySocket(clientSocket);
                        pio.returnIOPdata(pData);
                        // Clear the in-flight flag so the packet (still at front of
                        // queue) can be retried when the receiver reconnects.
                        offlineManager->clearFlag(recvId);
                        handleDisconnect(clientSocket);
                    }
                    // pData is reused for the next completion — do NOT delete it here
                    continue;
                }
                else
                {
                    // Fully sent — save receiverId BEFORE returning the
                    // packet to the pool (Bug 1: use-after-free fix).
                    std::string recvId = sessionManager->getUserIdBySocket(clientSocket);
                    bool bypassQ = sentPacket->bypassQueue;
                    sentPacket->isSending = false;
                    sentPacket->isSent = true;
                    PacketPool::Instance().returnPacket(sentPacket);
                    std::cout << "packet sent succesfully to \n"
                              << recvId;
                    // drain next packet
                    if (!bypassQ)
                    {
                        offlineManager->drainNext(recvId, clientSocket);
                    }
                }
            }

            pio.returnIOPdata(pData);
        }
    }
}

bool IOCPManager::postRecv(SOCKET s)
{
    PER_IO_OPERATION_DATA *pData = pio.borrowIOPdata();
    size_t savedId = pData->id;
    ZeroMemory(pData, sizeof(PER_IO_OPERATION_DATA));
    pData->id = savedId;
    pData->buffer.buf = NULL; // NULL
    pData->buffer.len = 0;    // 0 to telll the os not to lock memory from ram even if the socket is idle
    pData->operationType = 2; // 2- zero byte wait

    DWORD recvd = 0, flags = 0;
    int result = WSARecv(s, &pData->buffer, 1, &recvd, &flags, &pData->overlapped, NULL);

    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
    {
        int err = WSAGetLastError();
        Logger::warn("WSARecv failed on socket " + std::to_string(s) +
                     ", error: " + std::to_string(err));
        pio.returnIOPdata(pData);

        return false;
    }
    return true;
}
// sending packet to socket
bool IOCPManager::initiateSend(SOCKET s, Packet *p)
{
    PER_IO_OPERATION_DATA *pData = pio.borrowIOPdata();
    size_t savedId = pData->id;
    ZeroMemory(pData, sizeof(PER_IO_OPERATION_DATA));
    pData->id = savedId;

    // For a fully built packet, we just send header.size bytes from `data`
    p->isSending = true;
    p->isSentFail = false;
    uint32_t toCopy =  ntohl(*(uint32_t*)(p->data + 4)); + HEADER_SIZE;
    // if (toCopy > static_cast<int>(sizeof(pData->data)))
    // {
    //     toCopy = static_cast<int>(sizeof(pData->data)); // Safety clamp
    // }

   // std::memcpy(pData->data, p->data, toCopy);
    pData->buffer.buf = reinterpret_cast<char *>(p->data);
    pData->buffer.len = toCopy;
    pData->operationType = 0; // send

    // Track the packet for status updates on completion
    pData->packet = p;
    pData->totalToSend = toCopy;
    pData->bytesSent = 0;
    p->isSending = true;
    p->isSent = false;
    p->isSentFail = false;

    DWORD sent = 0;
    int result = WSASend(s, &pData->buffer, 1, &sent, 0, &pData->overlapped, NULL);
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
    {
        int err = WSAGetLastError();
        Logger::warn("WSASend failed on socket " + std::to_string(s) +
                     ", error: " + std::to_string(err));
        p->isSending = false;
        p->isSentFail = true;
        pio.returnIOPdata(pData);

        return false;
    }
    return true;
}
// // Dequeue the next outgoing packet from the session and start sending it
// void IOCPManager::queueSend(SOCKET s, Packet *p)
// {

//     if (p)
//     {
//         initiateSend(s, p);
//         // Note: p is NOT deleted here — it stays alive until send completes
//         // and its status (isSent/isSentFail) is updated by the completion handler
//     }
// }

void IOCPManager::handleDisconnect(SOCKET s)
{
    {
        std::lock_guard<std::mutex> lock(disconnectMtx);
        if (disconnectedSockets.count(s))
            return; // already handled
        disconnectedSockets.insert(s);
    }

    std::string userId = sessionManager->getUserIdBySocket(s);

    if (!userId.empty())
    {
        Logger::info("Client disconnected: " + userId);
        sessionManager->removeSession(userId);
    }
    else
    {
        Logger::info("Unknown socket disconnected: " + std::to_string(s));
    }

    // Extract shared_ptr from map and poison the buffer.
    // Any in-flight worker holding a shared_ptr copy will see the flag and bail out.
    // The buffer is destroyed when the last shared_ptr goes out of scope.
    std::shared_ptr<ConnectionBuffer> connBuf;
    {
        std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
        auto it = socketBuffers.find(s);
        if (it != socketBuffers.end())
        {
            connBuf = std::move(it->second);
            socketBuffers.erase(it);
        }
    }
    if (connBuf)
    {
        std::lock_guard<std::mutex> lock(connBuf->bufMtx);
        connBuf->disconnected.store(true, std::memory_order_release);
    }

    closesocket(s);
}

void IOCPManager::HandleDisconnectWithoutLock(SOCKET s)
{

    {
        std::lock_guard<std::mutex> lock(disconnectMtx);
        if (disconnectedSockets.count(s))
            return; // already handled
        disconnectedSockets.insert(s);
    }

    std::shared_ptr<ConnectionBuffer> connBuf;
    {
        std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
        auto it = socketBuffers.find(s);
        if (it != socketBuffers.end())
        {
            connBuf = std::move(it->second);
            socketBuffers.erase(it);
        }
    }
    if (connBuf)
    {
        std::lock_guard<std::mutex> lock(connBuf->bufMtx);
        connBuf->disconnected.store(true, std::memory_order_release);
    }

    closesocket(s);
}
void IOCPManager::shutdown()
{
    // Close listen socket to stop accept loop
    if (listenSocket != INVALID_SOCKET)
    {
        closesocket(listenSocket);
        listenSocket = INVALID_SOCKET;
    }

    // Post shutdown signals to all worker threads
    for (int i = 0; i < numWorkerThreads; i++)
    {
        PostQueuedCompletionStatus(iocpHandle, 0, 0, nullptr);
    }

    // Wait for all workers to finish
    for (auto &t : workerThreads)
    {
        if (t.joinable())
            t.join();
    }
    workerThreads.clear();

    if (iocpHandle != NULL)
    {
        CloseHandle(iocpHandle);
        iocpHandle = NULL;
    }

    Logger::info("IOCP server shut down");
}