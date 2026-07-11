
#include "MessageRouter.h"
#include "../utils/Logger.h"
#include "../network/IOCPManager.h"
#include <cstring>
#include "../pool/PacketPool.h"
#include "../authentication/SignUp.h"
#include "../authentication/AuthManager.h"

MessageRouter::MessageRouter(SessionManager *sm, GroupManager *gm)
    : sessionManager(sm), groupManager(gm)
{
}

bool MessageRouter::routePacket(Packet *packet, const std::string recvId)
{
    if(recvId.empty())return false;
    // checking everytime of session is inefficient as it need locks
    Session *receiver = sessionManager->findSession(recvId);
    if (receiver)
    {
        std::cout<<" sending initialised to :- "<<recvId<<std::endl;
        return receiver->sendPacket(packet,receiver->socket); // here we initialise sending
    
        //
    }
    else
    {
        std::cout<<" id not found in the session "<<recvId<<std::endl;
        return false;
    }
    return true;
}

void MessageRouter::routeGroupMessage(Packet *packet)
{
    const ChatMessagePayload* payload = packet->getPayload<ChatMessagePayload>();
    std::string recvId = AuthManager::UserIdToHexString(payload->receiver_id);
    std::string sendId = AuthManager::UserIdToHexString(payload->sender_id);

    Group *group = groupManager->getGroup(recvId);
    if (!group)
    {
        Logger::warn("Group '" + recvId + "' not found");
        return;
    }
    std::lock_guard<std::mutex>lk(groupManager->mtx);
    // Send to all group members except the sender
    for (const auto &memberId : group->members)
    {
        if (memberId == sendId)
            continue;
        Packet *outgoing = PacketPool::Instance().borrowPacket();
        if (outgoing == nullptr)
        {
            return;
        }
        std::memcpy(outgoing->data, packet->data, packet->header.payload_length + HEADER_SIZE);
        outgoing->header = packet->header;
        outgoing->in = outgoing->data + packet->header.payload_length + HEADER_SIZE;
        offManager->ManageCompletePacket(outgoing, memberId);
    }
    PacketPool::Instance().returnPacket(packet);
}

bool MessageRouter::handlePacket(Packet *packet, Session *sender)
{
    PacketType ptype = static_cast<PacketType>(packet->header.type); // got packet type to process

    bool bypassAuth = (ptype == PKT_LOGIN ||
                       ptype == PKT_SIGN_UP ||
                       ptype == PKT_OTP_REQ ||
                       ptype == PKT_OTP_VERIFY ||
                       ptype == PKT_TOKEN ||
                       ptype == PKT_REFRESH);

    if (!bypassAuth)
    {
        if (!AuthManager::ValidateSessionHotPath(sender))
        {
            Logger::warn("Unauthenticated packet type " + std::to_string(ptype) +
                         " rejected from socket " + std::to_string(sender->socket));
            if (authManager)
            {
                authManager->SendAuthFailure(sender, "Unauthorized access - please login");
            }
            PacketPool::Instance().returnPacket(packet);
            return true;
        }
    }

    switch (ptype)
    {
    case PKT_LOGIN:
        if (authManager)
        {
            std::string tempId = sender->userId;
         bool succes=   authManager->HandleLoginPacket(packet, sender);
         if(succes&&!sender->updated.load(std::memory_order_acquire)){
            sessionManager->updateNewId(tempId, sender);
            {
                const std::string id = sender->userId;
                Packet *p = PacketPool::Instance().borrowPacket();
              p->serializeUserId(sender->cached_user_id,sender->cached_user_id);
                p->bypassQueue = true;
                bool routed = routePacket(p, id);
                if (routed) {
                    std::cout << "id send succesfully !\n";
                } else {
                    PacketPool::Instance().returnPacket(p);
                }
            }

           
        }
        if(succes) offManager->notifySend(sender->userId);
    }
        else
        {
            PacketPool::Instance().returnPacket(packet);
        }
        break;

    case PKT_TOKEN: // for connecting
        if (authManager)
        {
            std::string tempId = sender->userId;
           bool succes= authManager->HandleTokenPacket(packet, sender);
          if(succes){
             if(!sender->updated.load(std::memory_order_acquire) )sessionManager->updateNewId(tempId, sender);
            offManager->notifySend(sender->userId);
          }
        }
        else
        {
            PacketPool::Instance().returnPacket(packet);
        }
        break;

    case PKT_REFRESH:
        if (authManager)
        {
            std::string tempId = sender->userId;
           bool succes= authManager->HandleRefreshPacket(packet, sender);
          if(succes){
             if(!sender->updated.load(std::memory_order_acquire) )
              sessionManager->updateNewId(tempId, sender);
              offManager->notifySend(sender->userId);
          }
        }
        else
        {
            PacketPool::Instance().returnPacket(packet);
        }
        break;

        // logout operation
    case PKT_LOGOUT:
        Logger::info("User '" + sender->userId + "' logged out");
        sessionManager->removeSession(sender->userId);
        PacketPool::Instance().returnPacket(packet);
        break;

    case PKT_PRIVATE_MESSAGE:
    {
        const ChatMessagePayload* payload = packet->getPayload<ChatMessagePayload>();
        std::string recvId = AuthManager::UserIdToHexString(payload->receiver_id);
        offManager->ManageCompletePacket(packet, recvId);
        break;
    }

    case PKT_GROUP_MESSAGE:
        routeGroupMessage(packet);
        break;

    case PKT_CREATE_GROUP:
    {
        const ChatMessagePayload* payload = packet->getPayload<ChatMessagePayload>();
        std::string recvId = AuthManager::UserIdToHexString(payload->receiver_id);
        std::string sendId = AuthManager::UserIdToHexString(payload->sender_id);
        if (groupManager->createGroup(recvId, sendId))
        {
            Logger::info("Group '" + recvId + "' created by " + sendId);
        }
        break;
    }

    case PKT_JOIN_GROUP:
    {
        const ChatMessagePayload* payload = packet->getPayload<ChatMessagePayload>();
        std::string recvId = AuthManager::UserIdToHexString(payload->receiver_id);
        std::string sendId = AuthManager::UserIdToHexString(payload->sender_id);
        if (groupManager->joinGroup(recvId, sendId))
        {
            Logger::info("User '" + sendId + "' joined group '" + recvId + "'");
        }
        break;
    }

    case PKT_LEAVE_GROUP:
    {
        const ChatMessagePayload* payload = packet->getPayload<ChatMessagePayload>();
        std::string recvId = AuthManager::UserIdToHexString(payload->receiver_id);
        std::string sendId = AuthManager::UserIdToHexString(payload->sender_id);
        if (groupManager->leaveGroup(recvId, sendId))
        {
            Logger::info("User '" + sendId + "' left group '" + recvId + "'");
        }
        break;
    }

    case PKT_FILE_START:
        Logger::info(" messagerouter for file start recid ; - "+sender->userId);
        filemanager->handleFileStart(packet, sender->userId);
        break;
    case PKT_FILE_CHUNK:
        filemanager->handleFileChunk(packet);
        break;
    case PKT_ROUND_END:
        std::cout<<" client asking for ack\n";
        filemanager->handleRoundEnd(packet);
        break;
    case PKT_FILE_END:
        filemanager->handleFileEnd(packet);
        break;
    case PKT_FILE_ACK:
        filemanager->onAckReceived(packet);
        break;
    case PKT_ACKNOWLEDGMENT:
        PacketPool::Instance().returnPacket(packet);
        break;
    case PKT_RESUME:
        break;
    case FILE_DWNLD_DISCONNECT_REQUEST:
        filemanager->HandleDisconnectRequest(packet);
        break;
    case DOWNLOAD_REQUEST:
        filemanager->HandleDownloadRequest(packet);
        break;

    case PKT_OTP_REQ:
        if (signUpManager)
            signUpManager->otpRequestHandler(packet, sender);
        break;

    case PKT_OTP_VERIFY:
        if (signUpManager)
            signUpManager->onOtpVerificationRequest(packet, sender);
        break;

    case PKT_SIGN_UP:
        if (signUpManager)
            signUpManager->signUpRequestHandler(packet, sender);
        break;

    default:
        Logger::warn("Unknown packet type: " + std::to_string(packet->header.type));
        break;
    }

    return true;
}
