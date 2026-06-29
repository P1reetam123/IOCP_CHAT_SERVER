#include "IOCPManager.h"
#include "IOContext.h"
#include "../offlineManager/ManageOffline.h"
#include "../session/SessionManager.h"
#include "../session/Session.h"
#include "../chat/MessageRouter.h"
#include "../utils/Logger.h"
#include <ws2tcpip.h>
#include <cstring>
#include <unordered_map>
#include"./protocol/Packet.h"
#include"./pool/PacketPool.h"
#include"./pool/SessionPool.h"
#include"./pool/IOContextPool.h"

struct ConnectionBuffer
{
    std::vector<char> buffer;
};
IOContextPool pio;

std::unordered_map<SOCKET, ConnectionBuffer> socketBuffers;
std::mutex IOCPManager::socketBuffersMutex;


IOCPManager::IOCPManager()
    : iocpHandle(NULL)
    , listenSocket(INVALID_SOCKET)
    , sessionManager(nullptr)
    , messageRouter(nullptr)
    , numWorkerThreads(0)
{
}

IOCPManager::~IOCPManager()
{
    shutdown();
}

bool IOCPManager::initialize(int port, SessionManager* sm, MessageRouter* mr,ManageOffline* mf)
{
    sessionManager = sm;
    offlineManager = mf;
    messageRouter = mr;
    WSADATA wsa;

    int res = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (res != 0)
    {
       std:: cout << " conection failed\n";
        return 1;
    }
    // Create listen socket
    listenSocket = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (listenSocket == INVALID_SOCKET) {
        Logger::error("Failed to create listen socket, error: " + std::to_string(WSAGetLastError()));
        return false;
    }

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<u_short>(port));
    address.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        Logger::error("Bind failed, error: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket);
        return false;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        Logger::error("Listen failed, error: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket);
        return false;
    }

    // Create IOCP handle
    iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (iocpHandle == NULL) {
        Logger::error("Failed to create IO completion port");
        closesocket(listenSocket);
        return false;
    }

    // Determine number of worker threads (2x CPU cores)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    numWorkerThreads = static_cast<int>(sysInfo.dwNumberOfProcessors * 2);
    if (numWorkerThreads < 2) numWorkerThreads = 2;

    // Launch worker threads
    for (int i = 0; i < numWorkerThreads; i++) {
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

    while (true) {
        sockaddr_in clientAddress;
        int addrLen = sizeof(clientAddress);

        SOCKET clientSocket = WSAAccept(listenSocket, (sockaddr*)&clientAddress, &addrLen, NULL, 0);
        if (clientSocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if (err == WSAEINTR || err == WSAENOTSOCK) {
                Logger::info("Accept loop terminated");
                break; // Server is shutting down
            }
            Logger::warn("WSAAccept failed, error: " + std::to_string(err));
            continue;
        }

        // Associate client socket with IOCP
        HANDLE result = CreateIoCompletionPort((HANDLE)clientSocket, iocpHandle, (ULONG_PTR)clientSocket, 0);
        if (result == NULL) {
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
            socketBuffers[clientSocket] = ConnectionBuffer();
        }

        Logger::info("New connection accepted (socket: " + std::to_string(clientSocket) + ")");

        // Post initial receive
        if (!postRecv(clientSocket)) {
            Logger::warn("Failed to post initial recv on new connection");
          // PacketPool::Instance().returnPacket(p);
        }
    }
}

void IOCPManager::workerThread()
{
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED lpOverlapped;

    while (true) {
        BOOL success = GetQueuedCompletionStatus(
            iocpHandle, &bytesTransferred, &completionKey, &lpOverlapped, INFINITE);

        // Check for shutdown signal (completionKey == 0 and bytesTransferred == 0)
        if (completionKey == 0 && bytesTransferred == 0 && lpOverlapped == nullptr) {
            break; // Shutdown signal
        }

        SOCKET clientSocket = (SOCKET)completionKey;
        PER_IO_OPERATION_DATA* pData = (PER_IO_OPERATION_DATA*)lpOverlapped;
        // socket closed during receving
        if ((!success || bytesTransferred == 0)) {
            // Connection closed or error
            //  If this was a pending send, recover the in-flight packet
            // so it can be retried instead of silently leaking from the pool.
            if (pData->operationType == 0 && pData->packet) {
                pData->packet->isSending = false;
                pData->packet->isSentFail = true;
                offlineManager->ManageCompletePacket(pData->packet, pData->packet->receiverId);
            }
            pio.returnIOPdata(pData);
            handleDisconnect(clientSocket);
            continue;
        }

        if (pData->operationType == 1) { // recv

        // Add received data to buffer
        {
            std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
            auto it = socketBuffers.find(clientSocket);
            if (it == socketBuffers.end()) {
                pio.returnIOPdata(pData);
                handleDisconnect(clientSocket);
                continue;
            }
            // this is slow create a circular buffer data structure
            auto& recvBuffer = it->second.buffer;
            recvBuffer.insert(
                recvBuffer.end(),
                pData->data,
                pData->data + bytesTransferred);
        }
         pio.returnIOPdata(pData);
    postRecv(clientSocket); 

        // Process packets from buffer
        while (true)
        {
            std::vector<char> packetData;
            bool hasPacket = false;

            // Safely extract packet from buffer
            {
                std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
                auto it = socketBuffers.find(clientSocket);
                if (it == socketBuffers.end()) {
                    // Socket already cleaned up — stop parsing.
                    // Note: pData was already deleted before this loop,
                    // so do NOT delete it again here.
                    break;
                }

                auto& recvBuffer = it->second.buffer;

                // Need at least header
                if (recvBuffer.size() < HEADER_SIZE)
                    break;

                uint32_t packetSize =
                    ntohl(*reinterpret_cast<uint32_t*>(recvBuffer.data()));

                if (packetSize < HEADER_SIZE)
                {
                    Logger::warn("Invalid packet size");
                    handleDisconnect(clientSocket);
                   // goto cleanup_recv;
                   break;
                }

                // Full packet not yet received
                if (recvBuffer.size() < packetSize)
                    break;

                // Extract packet data
            /// directly extract into the packet 
                packetData.assign(recvBuffer.begin(), recvBuffer.begin() + packetSize);
                hasPacket = true;

                // Remove consumed packet bytes this is also slow 
                recvBuffer.erase(recvBuffer.begin(), recvBuffer.begin() + packetSize);
            }

            if (!hasPacket)
                break;

            // Build packet from extracted data
            Packet* p = PacketPool::Instance().borrowPacket();
            if(p==nullptr){
               // Logger::info(" packet is ")
                break;
            }
            std::memcpy(p->data, packetData.data(), packetData.size());
            p->in = p->data + packetData.size();
            p->parseHeader();
                //this is slow 
            Session* s = sessionManager->findBySocket(clientSocket);

            if (!s)
            {
                s = SessionPool::Instance().borrowSession(clientSocket);
                if (s) {
                    s->iocp = this;
                    // this is also slow 
                    std::string tempId=std::to_string(static_cast<int>(clientSocket))+"id";
                    sessionManager->addSession(tempId, s);// temp user id will be used here 
                }
            }

            if (!s) {
                PacketPool::Instance().returnPacket(p);
                Logger::warn("Failed to get or create session for socket");
                handleDisconnect(clientSocket);
                break;
                //goto cleanup_recv;
            }

            bool handled =
                messageRouter->handlePacket(p, s);
                totalPacketRecieved++;

            if (!handled)
            {
                PacketPool::Instance().returnPacket(p);
                Logger::info("iocpmanager.cpp :  223");
            }
        }

       // cleanup_recv:
      
        }
        else if (pData->operationType == 0) { // send
            Packet* sentPacket = pData->packet;
    
                         sentPacket->isSending = false;
                         sentPacket->isSentFail = true;
         

            if (sentPacket) {
                pData->bytesSent += bytesTransferred;

                if (pData->bytesSent < pData->totalToSend) {
                    // Partial send: re-post WSASend for remaining bytes
                    int remaining = pData->totalToSend - pData->bytesSent;
                    pData->buffer.buf = pData->data + pData->bytesSent;
                    pData->buffer.len = remaining;

                    DWORD sent = 0;
                    ZeroMemory(&pData->overlapped, sizeof(OVERLAPPED));
                    int result = WSASend(clientSocket, &pData->buffer, 1, &sent, 0,
                                         &pData->overlapped, NULL);
                    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
                        Logger::warn("WSASend (partial resend) failed on socket " +
                                     std::to_string(clientSocket));
                        sentPacket->isSending = false;
                        sentPacket->isSentFail = true;
                        // Save receiverId before returning pData — after returnIOPdata,
                        // pData (and its pointers) may be reused by another thread.
                        std::string recvId = sentPacket->receiverId;
                        pio.returnIOPdata(pData);
                        // Clear the in-flight flag so the packet (still at front of
                        // queue) can be retried when the receiver reconnects.
                        offlineManager->clearFlag(recvId);
                        handleDisconnect(clientSocket);
                    }
                    // pData is reused for the next completion — do NOT delete it here
                    continue;
                } else {
                    // Fully sent — save receiverId BEFORE returning the
                    // packet to the pool (Bug 1: use-after-free fix).
                    std::string recvId = sentPacket->receiverId;
                    sentPacket->isSending = false;
                    sentPacket->isSent = true;
                    PacketPool::Instance().returnPacket(sentPacket);
                        std::cout<<"packet has been sent \n";
                    // drain next packet 
                    offlineManager->drainNext(recvId, clientSocket);
                }
            }


            pio.returnIOPdata(pData);
        }
    }
}

bool IOCPManager::postRecv(SOCKET s)
{
PER_IO_OPERATION_DATA* pData = pio.borrowIOPdata();
    size_t savedId = pData->id;
    ZeroMemory(pData, sizeof(PER_IO_OPERATION_DATA));
    pData->id = savedId;
    pData->buffer.buf = pData->data;
    pData->buffer.len = sizeof(pData->data);
    pData->operationType = 1; // recv

    DWORD recvd = 0, flags = 0;
    int result = WSARecv(s, &pData->buffer, 1, &recvd, &flags, &pData->overlapped, NULL);

    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        int err = WSAGetLastError();
        Logger::warn("WSARecv failed on socket " + std::to_string(s) +
                     ", error: " + std::to_string(err));
        pio.returnIOPdata(pData);
       
        return false;
    }
    return true;
}
 // sending packet to socket
bool IOCPManager::initiateSend(SOCKET s, Packet* p)
{
PER_IO_OPERATION_DATA* pData = pio.borrowIOPdata();
    size_t savedId = pData->id;
    ZeroMemory(pData, sizeof(PER_IO_OPERATION_DATA));
    pData->id = savedId;

    // For a fully built packet, we just send header.size bytes from `data`
    int toCopy = p->header.size;
    if (toCopy > static_cast<int>(sizeof(pData->data))) {
        toCopy = static_cast<int>(sizeof(pData->data)); // Safety clamp
    }
    
    std::memcpy(pData->data, p->data, toCopy);
    pData->buffer.buf = pData->data;
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
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
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
// Dequeue the next outgoing packet from the session and start sending it
void IOCPManager::queueSend(SOCKET s,Packet* p)
{
    
    if (p) {
        initiateSend(s, p);
        // Note: p is NOT deleted here — it stays alive until send completes
        // and its status (isSent/isSentFail) is updated by the completion handler
    }
}

void IOCPManager::handleDisconnect(SOCKET s)
{
    {
        std::lock_guard<std::mutex> lock(disconnectMtx);
        if (disconnectedSockets.count(s)) return; // already handled
        disconnectedSockets.insert(s);
    }

    std::string userId = sessionManager->getUserIdBySocket(s);

    if (!userId.empty()) {
        Logger::info("Client disconnected: " + userId);
        sessionManager->removeSession(userId);
    } else {
        Logger::info("Unknown socket disconnected: " + std::to_string(s));
    }
    {
        std::lock_guard<std::mutex> lock(IOCPManager::socketBuffersMutex);
        socketBuffers.erase(s);
    }

    closesocket(s);

}

void IOCPManager::shutdown()
{
    // Close listen socket to stop accept loop
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
        listenSocket = INVALID_SOCKET;
    }

    // Post shutdown signals to all worker threads
    for (int i = 0; i < numWorkerThreads; i++) {
        PostQueuedCompletionStatus(iocpHandle, 0, 0, nullptr);
    }

    // Wait for all workers to finish
    for (auto& t : workerThreads) {
        if (t.joinable()) t.join();
    }
    workerThreads.clear();

    if (iocpHandle != NULL) {
        CloseHandle(iocpHandle);
        iocpHandle = NULL;
    }

    Logger::info("IOCP server shut down");
}