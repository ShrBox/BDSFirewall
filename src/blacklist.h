#pragma once
#include <string>
#include <vector>

namespace BlackList {
    void add(std::string& address);
    void remove(std::string& address);
    bool query(std::string& address);
}