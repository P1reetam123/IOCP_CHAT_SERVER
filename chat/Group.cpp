#include "Group.h"

void Group::addMember(const std::string& userId)
{
    if (!isMember(userId)) {
        members.push_back(userId);
    }
}

void Group::removeMember(const std::string& userId)
{
    auto it = std::find(members.begin(), members.end(), userId);
    if (it != members.end()) {
        members.erase(it);
    }
}

bool Group::isMember(const std::string& userId) const
{
    return std::find(members.begin(), members.end(), userId) != members.end();
}
