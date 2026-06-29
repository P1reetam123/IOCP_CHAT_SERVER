#include "FileTransferManager.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <cstring>
#include <fstream>
#include "../chat/MessageRouter.h"
#include <filesystem>
#include <algorithm>
#include"./pool/PacketPool.h"
// activeTransfers
//  note desig client side so that only one file download request come to server

bool FileTransferManager::checkGrp(const std::string &id)
{

    return id.size() >= 3 && id.substr(0, 3) == "GRP";
}
// send the download link to all user and push state to map to find when user want the download

void FileTransferManager::start()
{
    downloadThread = std::thread(&FileTransferManager::sendDownloadLinkLoop, this);
    for (size_t i = 0; i < TRANSFER_POOL_SIZE; ++i) {
        transferWorkers_.emplace_back(&FileTransferManager::transferWorkerLoop, this);
    }
}

void FileTransferManager::transferWorkerLoop() {
    while (true) {
        TransferTask task;
        {
            std::unique_lock<std::mutex> lk(transferMtx_);
            transferCv_.wait(lk, [this] { return stopTransferPool_ || !transferQueue_.empty(); });
            if (stopTransferPool_ && transferQueue_.empty()) return;
            task = transferQueue_.front();
            transferQueue_.pop();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1)); // the original delay before starting download stream
        HandleFileTransfer(task.fileName, task.receiverId, task.upId, task.startBytes);
    }
}

void FileTransferManager::sendDownloadLinkLoop()
{
    while (true)
    {
        std::unique_lock<std::mutex> lk(downloadMtx);
        downloadCv.wait(lk, [this]
                        { return stopLoop || !completedUpload.empty(); });
        if (stopLoop && completedUpload.empty())
            break;

        while (!completedUpload.empty())
        {
            TransferState *state = completedUpload.front();
            completedUpload.pop();
            lk.unlock(); // unlock while doing I/O

            std::string receiver = state->receiverId;
            
           // Logger::info("there is download link in queue");

        Packet* p = PacketPool::Instance().borrowPacket();
            p->senderId = state->senderId;
            p->receiverId = state->receiverId;
            p->header.type = DOWNLOAD_LINK; 
            // senderid, reciever id , uploadid,filename,filelength,timestamp,
            std::string payload = state->uploadId + " " + state->fileName + " " + std::to_string(state->totalLength) + " " + state->timestamp;
            p->serialize(DOWNLOAD_LINK, state->senderId, state->receiverId, payload);
            {
                std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
                downloadableFiles[state->uploadId] = state;
               // Logger::info("Link pushed into downloadable files  ");
            }

            if (checkGrp(receiver))
            {
                route->routeGroupMessage(p);
            }
            else
            {
                off->ManageCompletePacket(p, p->receiverId);
               // Logger::info("Link routed to the reciever ");
            }
            // downloadableFiles[state->uploadId] = state;

            lk.lock(); // relock for next iteration check
        }
    }
}
// transfer chunks function
// handle dwonload function

// download reques layout
//----------------------------------------------
// recid ,upid,bytes,
//---------------------------------------------
void FileTransferManager::HandleDownloadRequest(Packet *p)
{

    // sender will send download request with how much he has bytes he has recieved
    // we will set round =0 at every dwnld request
//Logger::info("I got the download request");
    std::string upId, receiverId, bytes;
    char *st = p->data + HEADER_SIZE;
    size_t len = p->header.size - HEADER_SIZE;
    std::string raw(st, len);
     PacketPool::Instance().returnPacket(p);

    size_t pos = 0;
// recid,upid,bytes 
    while (pos < len && raw[pos] != ' ')
        receiverId.push_back(raw[pos++]);
    pos++;
    while (pos < len && raw[pos] != ' ')
        upId.push_back(raw[pos++]);
    pos++;
    while (pos < len && raw[pos] != ' ')
        bytes.push_back(raw[pos++]);
    // chheck for parsing
    if (receiverId.empty() || upId.empty() || bytes.empty())
    {
        Logger::error("HandleDownloadRequest: failed to parse payload");
        return;
    }

    TransferState *state = nullptr;
    {
        std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
        auto it = downloadableFiles.find(upId);
        if (it == downloadableFiles.end())
        {

            // Unlock is implicit via guard destructor before we call send.
        }
        else
        {
            state = it->second;
            Logger::info("atate assigned  ");
        }
    }

    if (!state)
    {
        SendErrorPacket(receiverId, upId, "File not found — ask sender to re-upload.");
        return;
    }
    size_t startBytes = 0;
    try
    {
        startBytes = static_cast<size_t>(std::stoul(bytes));
    }
    catch (const std::exception &e)
    {
        Logger::error("HandleDownloadRequest: invalid bytes value: " + bytes);
        SendErrorPacket(receiverId, upId, "Malformed request.");
        return;
    }
    se->setRecievingFileTrue(receiverId);

    // send start file packet to receiver

    // length ||pkt||senderId|| receiverid||filesize||filename||uplaodId||totalChunks||timstamp|| length
    std::string payload = std::to_string(state->totalLength) + " " + state->fileName + " " + state->uploadId + " " + std::to_string(state->totalChunks) + " " + state->timestamp;
    SendStartAck(state->senderId, state->receiverId, state->uploadId, payload);

    // push task to bounded thread pool
    {
        std::lock_guard<std::mutex> lk(transferMtx_);
        transferQueue_.push({state->fileName, receiverId, upId, startBytes});
    }
    transferCv_.notify_one();
}
void FileTransferManager::HandleFileTransfer(const std::string &fileName, const std::string &receiverId, const std::string &upId, const size_t startBytes)
{
 ///   Logger::info("handle file transfer stated  ");
    TransferState *state = nullptr;
    {
        std::lock_guard<std::mutex> mapLk(downloadableFilesMtx);
        auto it = downloadableFiles.find(upId);
        if (it == downloadableFiles.end())
        {
            Logger::error("HandleFileTransfer: state for " + upId + " gone before transfer started");
            SendErrorPacket(receiverId, upId, "Internal error — please retry.");
            return;
        }
        state = it->second;
    }

    const std::string dir = saveDirectory + fileName;
    std::ifstream file;
    bool opened = false;

    for (int i = 0; i < 4 && !opened; i++)
    {
        try
        {
            // Set exception mask BEFORE opening to catch open failures
            file.exceptions(std::fstream::failbit | std::fstream::badbit);

            // Open with in|out|binary|ate.
            // 'ate' starts at end, allowing immediate tellp().
            file.open(dir, std::ios::in | std::ios::binary | std::ios::ate);

            opened = true;
        }
        catch (const std::ios_base::failure &e)
        {
            Logger::error("Opening failed: " + std::string(e.what()));
            // Optional: clear bits to reuse the 'file' object in next iteration
            file.clear();
        }

        if (i < 3)
        { // Don't sleep after the last failed attempt
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    if (!opened)
    {
        // Handle total failure (e.g., return or throw)
        Logger::error("can't open the file send the receiver errro ");
        // send retry later message
        SendErrorPacket(receiverId, upId, "try after some time ");
        se->setRecievingFileFalse(receiverId);
        return;
    }
    const std::streamoff rawLength = file.tellg();
    if (rawLength < 0)
    {
        Logger::error("HandleFileTransfer: tellg() failed for " + dir);
        SendErrorPacket(receiverId, upId, "Could not determine file size.");
        se->setRecievingFileFalse(receiverId);
        return;
    }

    const size_t length = static_cast<size_t>(rawLength);
    if (startBytes > length)
    {
        Logger::error("HandleFileTransfer: startBytes(" + std::to_string(startBytes) +
                      ") > fileLength(" + std::to_string(length) + ")");
        SendErrorPacket(receiverId, upId, "Invalid resume offset.");
        se->setRecievingFileFalse(receiverId);
        return;
    }
    file.seekg(0, std::ios::beg);
    file.seekg(static_cast<std::streamoff>(startBytes));

    // transfer loop
    TransferSession ts;

    ts.round = 0;
    ts.bytes_remaining = length - startBytes;

    bool disconnect = false;
    while (ts.bytes_remaining > 0 && !disconnect)
    {

        //  fill the buffer for this round

        size_t chunk_idx = 0; // this will tell the last idx of chunks in the buffer
        while (ts.bytes_remaining > 0 && chunk_idx < 1024)
        {
            const size_t toRead = std::min<size_t>(4000, ts.bytes_remaining);

            std::vector<char> memblock(toRead);

            file.read(&memblock[0], static_cast<std::streamsize>(toRead));
            const size_t actualRead = static_cast<size_t>(file.gcount());

            if (actualRead == 0)
            { //********************* */
                Logger::warn("HandleFileTransfer: read returned 0 bytes unexpectedly");
                break;
            }

            if (actualRead < toRead)
                memblock.resize(actualRead);

            ts.bytes_remaining -= actualRead;

            ts.buffer.push_back(std::move(memblock));

            ts.missingChunks.push(chunk_idx);

            ++chunk_idx;
        }

        if (ts.buffer.empty())
            break; // nothing was read (unexpected EOF before bytes_remaining hit 0)
        while (!ts.missingChunks.empty())
        {

            while (!ts.missingChunks.empty())
            {
                const uint32_t idx = ts.missingChunks.front();

                ts.missingChunks.pop();

                if (idx >= ts.buffer.size())
                {
                    Logger::warn("HandleFileTransfer: client requested out-of-range chunk " +
                                 std::to_string(idx));
                    continue;
                }
// upid ,idx ,data
               Packet* p = PacketPool::Instance().borrowPacket();
                p->serializeChunk(upId, std::to_string(idx), ts.buffer[idx]);
                // route the packet
                off->ManageCompletePacket(p, receiverId);
                // detect the whether the receiver is connected or not
             //   p.release();
            }
            SendRoundEnd(receiverId, upId, ts.round, chunk_idx);
            // ask for acknowledment with round // it will block until ack comes or timeout
        // ********************
       
            std::vector<uint32_t> missing = waitForAck(upId, ts.round, /*ms=*/5000);
            // reciev acknowledment and add missing chunks index into queue
            // check whether recievr is active or not
            // may be race condition here 
//             disconnect = se->checkReciever(receiverId);
//   if (disconnect){
//     Logger::info(" reciever disconnected  ");
//                 break;

//   }
            if (!missing.empty() && missing[0] == static_cast<uint32_t>(-1))
            {
              //  Logger::info(" all chunks has been recieved  ");
                // sentinel value means all chunks have been received
                continue;
            }
            else if (!missing.empty())
            {
                //Logger::info(" some chunks has been recieved  ");
                 for (uint32_t m : missing)
                {
                    if (m < ts.buffer.size())
                        ts.missingChunks.push(m);
                    else
                        Logger::warn("HandleFileTransfer: ignoring invalid missing idx " +
                                     std::to_string(m));
                }
            }

            else

            { // if empty resent again whole buffer timeout
              for (size_t i = 0; i < ts.buffer.size(); ++i)
                    ts.missingChunks.push(static_cast<uint32_t>(i));
            }
        }
       
        if (disconnect)
        {
            break;
        }

        ts.round++;
        

        ts.buffer.clear(); // clear the buffer for the next round
        Logger::info(" cleared buffer going for next");
    }
    // at the end send the end ack along with check sum
    if (!disconnect)
        SendEndAck(receiverId, upId, state->checkSum);
se->setRecievingFileFalse(receiverId);
    file.close();
}
// length ||pkt||senderId|| receiverid||filesize||filename||uplaodId||totalChunks||timstamp|| length
void FileTransferManager::SendStartAck(const std::string &sendId, const std::string &recId, const std::string &upId, const std::string &payload)
{

  Packet* p = PacketPool::Instance().borrowPacket();
    p->senderId = sendId;
    p->receiverId = recId;
    p->header.type = PKT_FILE_START;
    p->serialize(PKT_FILE_START, sendId, recId, payload);
    off->ManageCompletePacket(p, recId);
  //  p.release();
}

// upid// round // msissing chunks seprated by space
void FileTransferManager::onAckReceived(Packet *p)
{
if (p->header.size < HEADER_SIZE)
    {
        Logger::error("onAckReceived: malformed ACK packet");
        return;
    }
   
   

   const char*  st  = p->data + HEADER_SIZE;


    const size_t len = static_cast<size_t>(p->header.size) - HEADER_SIZE;

    const std::string raw(st, len);
 PacketPool::Instance().returnPacket(p);


    size_t pos = 0;
  
    std::string upId, roundStr;
 // upId , roundstr,missing chunks
    while (pos < raw.size() && raw[pos] != ' ') upId.push_back(raw[pos++]);
    if (pos < raw.size()) ++pos;
    while (pos < raw.size() && raw[pos] != ' ') roundStr.push_back(raw[pos++]);
    if (pos < raw.size()) ++pos;
 
    if (upId.empty() || roundStr.empty())
    {
        Logger::error("onAckReceived: failed to parse upId/round");
        return;
    }
// Logger::info(roundStr);
    // FIX 26: Wrap stoi — malformed ACK should not crash the server.
    uint32_t round = 0;
    try { round = static_cast<uint32_t>(std::stoul(roundStr)); }
    catch (const std::exception& e)
    {
        Logger::error("onAckReceived: invalid round value: " + roundStr);
        return;
    }
 //Logger::info(" writing missing chunks ");
    std::vector<uint32_t> missingChunks;
    while (pos < raw.size())
    {
        Logger::info(" in while loop  ");
        std::string idxStr;
        while (pos < raw.size() && raw[pos] != ' ') idxStr.push_back(raw[pos++]);
        if (pos < raw.size()) ++pos;
 //Logger::info(idxStr);
        if (!idxStr.empty())
        {
            try { missingChunks.push_back(static_cast<uint32_t>(std::stoul(idxStr))); }
            catch (...) { /* skip malformed index */ }
        }
    }
//Logger::info(" outside the while ");
    {
        std::lock_guard<std::mutex> lk(ackMtx);
        // FIX 27: Only overwrite if the new round >= stored round to avoid a
        //         delayed duplicate ACK stomping over a newer one.
        Logger::info(" modifing pending acks  ");
        auto it = pendingAcks.find(upId);
        if (it == pendingAcks.end() || it->second.round <= round)
            pendingAcks[upId] = { round, std::move(missingChunks) };
    }
   // Logger::info("missing chunks has been written infoming the thread");
    ackCv.notify_all();
}

std::vector<uint32_t> FileTransferManager::waitForAck(const std::string &upId,
                                                      uint32_t round,
                                                      int timeoutMs)
{

    std::unique_lock<std::mutex> lk(ackMtx);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);

    bool arrived = ackCv.wait_until(lk, deadline, [&]
                                    {
        auto it = pendingAcks.find(upId);
         if (it != pendingAcks.end()) {
        // Only log and compare if the item exists
       // Logger::info(std::to_string(it->second.round) + "===" + std::to_string(round));
        return it->second.round == round;
    }
    
    // Item not found yet
    return false; });

    if (!arrived)
    {
        Logger::warn("ACK timeout for " + upId + " round " + std::to_string(round));
        // On timeout, assume all chunks were lost — retransmit everything
        return {}; // caller interprets empty as "retransmit current batch"
        // Alternative: return a sentinel that triggers full retransmit
    }
//Logger::info("ack arrived ");

    std::vector<uint32_t> missing = std::move(pendingAcks[upId].missing);
    pendingAcks.erase(upId);
    if(missing.empty()){
        // if empty
        missing.push_back(-1);

    }
    return missing;
}

void FileTransferManager::SendRoundEnd(const std::string &receiverId,
                                       const std::string &upId,
                                       uint32_t round,
                                       const size_t roundLastIdx)
{

    // LAYOUT for sending round end ack packet
    //-----------------------------------------------
    // HEADER ||  || UP ID||LAST INDEX OF ROUND
    //
    //------------------------------------------------
 

  Packet* p = PacketPool::Instance().borrowPacket();
    p->receiverId = receiverId;
    p->header.type = PKT_ROUND_END;
    p->serialize(PKT_ROUND_END, upId,  std::to_string(roundLastIdx), "");
    off->ManageCompletePacket(p, receiverId);
   
}

// end packet layout
//--------------------------------------
// upID|| recId||checksum
//------------------------------------
void FileTransferManager::SendEndAck(
    const std::string &recId,
    const std::string &upId,
    uint32_t checksum)
{
    //std::string payload = upId + " " + std::to_string(checksum);
   Packet* p = PacketPool::Instance().borrowPacket();
    p->receiverId = recId;
    p->header.type = PKT_FILE_END;
    p->serialize(PKT_FILE_END, upId, recId, std::to_string(checksum));
    off->ManageCompletePacket(p, recId);
   // Logger::info("send end file ");
   
}

void FileTransferManager::SendErrorPacket(const std::string &recId,
                                          const std::string &upId,
                                          const std::string &reason)
{
    std::string payload = upId + " " + reason;
  Packet* p = PacketPool::Instance().borrowPacket();
    p->receiverId = recId;
    p->header.type = PKT_FILE_ERROR;
    p->serialize(PKT_FILE_ERROR, "", recId, payload);
    off->ManageCompletePacket(p, recId);
   
}

// handle the disconnect packet

// packet layout
//--------------------------------------------------------
// length|| PKT type || sender id || upId||
//--------------------------------------------------------
// we need to extract receiver id only as one receiver is downloading one file at one time
// later during polishing direct read from packet data no need to alocate memory  and copying
void FileTransferManager::HandleDisconnectRequest(Packet *p)
{
  if (p->header.size < HEADER_SIZE)
    {
        Logger::error("HandleDisconnectRequest: malformed packet");
        return;
    }
 
    const char*  st  = p->data + HEADER_SIZE;
    const size_t len = static_cast<size_t>(p->header.size) - HEADER_SIZE;
    const std::string raw(st, len);
  PacketPool::Instance().returnPacket(p);

    std::string recId;
    for (size_t pos = 0; pos < raw.size() && raw[pos] != ' '; ++pos)
        recId.push_back(raw[pos]);
 
    if (recId.empty())
    {
        Logger::error("HandleDisconnectRequest: empty receiver ID");
        return;
    }
 
    se->setRecievingFileFalse(recId);
}
