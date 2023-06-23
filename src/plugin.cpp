/**
 * @file plugin.cpp
 * @brief The main file of the plugin
 */

#include <llapi/LoggerAPI.h>
#include <llapi/mc/RakNet.hpp>
#include <llapi/HookAPI.h>
#include "blacklist.h"

// We recommend using the global logger.
extern Logger logger;

/**
 * @brief The entrypoint of the plugin. DO NOT remove or rename this function.
 *        
 */
std::unordered_map<std::string, unsigned short> LoginPacketTries;

void PluginInit()
{
    std::thread([]{
        while (!ll::isServerStopping()) {
            LoginPacketTries.clear();
            std::this_thread::sleep_for(std::chrono::seconds(20));
        }
    }).detach();
    logger.info("Firewall enabled!");
}

std::string splitAddress(std::string& address) {
    auto pos = address.find(':');
    if (pos != std::string::npos) {
        return address.substr(0, pos);
    }
    return {};
}

struct RakPacket
{
    RakNet::SystemAddress systemAddress;
    RakNet::RakNetGUID guid;
    unsigned int length;
    uint32_t bitSize;
    unsigned char* data;
    bool deleteData;
    bool wasGeneratedLocally;
};

void RakAddToBanList(RakNet::RakPeer* _this, std::string& address, unsigned int time) {
    SymCall("?AddToBanList@RakPeer@RakNet@@UEAAXPEBDI@Z", void, RakNet::RakPeer*, const char*, unsigned int)(_this, address.c_str(), time);
}
// MotdFlood protection
TInstanceHook(RakPacket*, "?Receive@RakPeer@RakNet@@UEAAPEAUPacket@2@XZ", RakNet::RakPeer) {
    RakPacket* pkt = original(this);
    if (pkt && (pkt->data[0] == 0x01 || pkt->data[0] == 0x07)) {
        std::string address = pkt->systemAddress.ToString(false, 124);
        if (!address.empty()) {
//            if (BlackList::query(address)) {
//                return pkt;
//            }
            LoginPacketTries[address] = ++LoginPacketTries[address];
            logger.debug("IP: {} Tries: {}", address, LoginPacketTries[address]);
            if (LoginPacketTries[address] > 25) {
                logger.warn("MotdFlood detected! IP: {}", address);
                RakAddToBanList(this, address, 0);
                logger.warn("IP: {} has been added into BlackList", address);
                return pkt;
            }
        }
    }
    return pkt;
}