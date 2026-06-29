#pragma once
#include <string>
#include <vector>
#include <algorithm>

class Group
{
public:
    std::string group_id;
    std::string admin_id;
    std::vector<std::string> members;

public:
    void addMember(const std::string& userId);
    void removeMember(const std::string& userId);
    bool isMember(const std::string& userId) const;
};