#pragma once

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
    // checking everytime of session is inefficient as it need locks
    Session *receiver = sessionManager->findSession(recvId);
    if (receiver)
    {
        packet->receiverId=recvId;
        receiver->sendPacket(packet); // here we initialise sending
        counter++;
        //
    }
    else
    {
        return false;
    }
    return true;
}

void MessageRouter::routeGroupMessage(Packet *packet)
{
    Group *group = groupManager->getGroup(packet->receiverId);
    if (!group)
    {
        Logger::warn("Group '" + packet->receiverId + "' not found");
        return;
    }

    // Send to all group members except the sender
    for (const auto &memberId : group->members)
    {
        if (memberId == packet->senderId)
            continue;
        Packet *outgoing = PacketPool::Instance().borrowPacket();
        if (outgoing == nullptr)
        {
            return;
        }
        std::memcpy(outgoing->data, packet->data, packet->header.size);
        outgoing->header = packet->header;
        outgoing->in = outgoing->data + packet->header.size;
        //  member->queuePacket(outgoing);
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
            authManager->HandleLoginPacket(packet, sender);
            sessionManager->updateNewId(tempId, sender);
            {
                const std::string id = sender->userId;
                Packet *p = PacketPool::Instance().borrowPacket();
                p->serialize(PKT_USER_ID, "server", id, id);
                bool routed = routePacket(p, id);
                if (routed)
                    std::cout << "id send succesfully !\n";
            }

            offManager->notifySend(sender->userId);
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
            authManager->HandleTokenPacket(packet, sender);
            sessionManager->updateNewId(tempId, sender);
            offManager->notifySend(sender->userId);
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
            authManager->HandleRefreshPacket(packet, sender);
            sessionManager->updateNewId(tempId, sender);
            offManager->notifySend(sender->userId);
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
        receivedPrivateMsg++;
        offManager->ManageCompletePacket(packet, packet->receiverId);
        break;
    }

    case PKT_GROUP_MESSAGE:
        routeGroupMessage(packet);
        break;

    case PKT_CREATE_GROUP:
        // group id         // admin id
        if (groupManager->createGroup(packet->receiverId, packet->senderId))
        {
            Logger::info("Group '" + packet->receiverId + "' created by " + packet->senderId);
        }
        break;

    case PKT_JOIN_GROUP:
        if (groupManager->joinGroup(packet->receiverId, packet->senderId))
        {
            Logger::info("User '" + packet->senderId + "' joined group '" + packet->receiverId + "'");
        }
        break;

    case PKT_LEAVE_GROUP:
        if (groupManager->leaveGroup(packet->receiverId, packet->senderId))
        {
            Logger::info("User '" + packet->senderId + "' left group '" + packet->receiverId + "'");
        }
        break;

    case PKT_FILE_START:
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
        //   Logger::info("Received PKT_RESUME packet");
        // filemanager->HandleResume(packet);
        break;
    case FILE_DWNLD_DISCONNECT_REQUEST:
        //   Logger::info("Received FILE_DWNLD_DISCONNECT_REQUEST packet");
        filemanager->HandleDisconnectRequest(packet);
        break;
    case DOWNLOAD_REQUEST:
        filemanager->HandleDownloadRequest(packet);
        break;

    case PKT_OTP_REQ:
        if (signUpManager)
            signUpManager->otpRequestHandler(packet);
        break;

    case PKT_OTP_VERIFY:
        if (signUpManager)
            signUpManager->onOtpVerificationRequest(packet);
        break;

    case PKT_SIGN_UP:
        if (signUpManager)
            signUpManager->signUpRequestHandler(packet);
        break;

    default:
        Logger::warn("Unknown packet type: " + std::to_string(packet->header.type));
        break;
    }

    return true;
}
