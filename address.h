#pragma once
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthIpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Address final
{
    Ip attackerIp = Ip();
    Ip senderIp = Ip();
    Ip targetIp = Ip();

    Mac attackerMac = Mac();
    Mac senderMac = Mac();
    Mac targetMac = Mac();
};
#pragma pack(pop)
