#include "pch.h"

std::map<Ip, Mac> macAddress;

Mac getMacAddress(pcap_t *pcap, Mac attackerMac, Ip attackerIp, Ip targetIp, char *mac)
{
    auto it = macAddress.find(targetIp);
    if(it != macAddress.end())
    {
        return it->second;
    }

    arpRequest(pcap, attackerMac, attackerIp, targetIp, mac);

    Mac findMac = Mac(mac);
    macAddress[targetIp] = findMac;
    return findMac;
}
