#include "blacklist.h"

namespace BlackList {
    std::vector<std::string> BlackList;
    void add(std::string& address) {
        BlackList.push_back(address);
    }
    void remove(std::string& address) {
        auto it = std::find(BlackList.begin(), BlackList.end(), address);
        if (it != BlackList.end())
            BlackList.erase(it);
    }
    bool query(std::string& address) {
        auto it = std::find(BlackList.begin(), BlackList.end(), address);
        if (it != BlackList.end()) {
            return true;
        }
        return false;
    }
}