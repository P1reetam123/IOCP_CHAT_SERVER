#pragma once
#include <unordered_map>
#include <mutex>
#include "Group.h"

class GroupManager
{
private:
    std::unordered_map<std::string, Group> groups;
    std::mutex mtx;

public:
    bool createGroup(const std::string& groupId, const std::string& adminId);
    bool joinGroup(const std::string& groupId, const std::string& userId);
    bool leaveGroup(const std::string& groupId, const std::string& userId);
    Group* getGroup(const std::string& groupId);
};