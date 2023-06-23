/**
 * @file plugin.cpp
 * @brief The main file of the plugin
 */

#include <llapi/LoggerAPI.h>
#include "version.h"
#include <llapi/mc/ServerNetworkHandler.hpp>
#include <llapi/mc/NetworkIdentifier.hpp>
#include <llapi/mc/LoginPacket.hpp>
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
            std::this_thread::sleep_for(std::chrono::seconds(60));
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

TInstanceHook(void, "?handle@ServerNetworkHandler@@UEAAXAEBVNetworkIdentifier@@AEBVLoginPacket@@@Z", ServerNetworkHandler, NetworkIdentifier* ni, const LoginPacket* pkt) {
    std::string address = ni->getIP();
    if (!address.empty()) {
        std::string newAddress = splitAddress(address);
        if (BlackList::query(newAddress)) {
            return;
        }
        LoginPacketTries[newAddress] = ++LoginPacketTries[newAddress];
        logger.debug("IP: {} Tries: {}", address, LoginPacketTries[newAddress]);
        if (LoginPacketTries[newAddress] >= 20) {
            logger.warn("LoginPacketFlood detected! IP: {}", address);
            BlackList::add(newAddress);
            logger.warn("IP: {} has been added into BlackList", newAddress);
            return;
        }
    }
    return original(this, ni, pkt);
}