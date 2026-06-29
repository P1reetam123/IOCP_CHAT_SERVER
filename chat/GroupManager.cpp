#include "GroupManager.h"

bool GroupManager::createGroup(const std::string& groupId, const std::string& adminId)
{
    std::lock_guard<std::mutex> lock(mtx);
    if (groups.find(groupId) != groups.end()) {
        return false; // Group already exists
    }
    Group g;
    g.group_id = groupId;
    g.admin_id = adminId;
    g.addMember(adminId); // Admin is automatically a member
    groups[groupId] = g;
    return true;
}

bool GroupManager::joinGroup(const std::string& groupId, const std::string& userId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = groups.find(groupId);
    if (it == groups.end()) return false;
    if (it->second.isMember(userId)) return false;
    it->second.addMember(userId);
    return true;
}

bool GroupManager::leaveGroup(const std::string& groupId, const std::string& userId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = groups.find(groupId);
    if (it == groups.end()) return false;
    if (!it->second.isMember(userId)) return false;
    it->second.removeMember(userId);
    // If no members left, remove the group
    if (it->second.members.empty()) {
        groups.erase(it);
    }
    return true;
}

Group* GroupManager::getGroup(const std::string& groupId)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = groups.find(groupId);
    if (it != groups.end()) return &(it->second);
    return nullptr;
}