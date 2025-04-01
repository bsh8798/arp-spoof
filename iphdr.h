#pragma once

#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final
{
    u_int8_t IHL:4;  //IP Header Length(/4), HBO(little endian) -> last 4bits
    u_int8_t version:4;  //IPv4 or IPv6, first 4bits
    u_int8_t service;  //service quality
    u_int16_t total_length;  //ip total length
    u_int16_t identification;  //unique number of segmented packet
    u_int16_t flag_offset;  //segmented packet's number = location in origin data
    u_int8_t TTL;  //time to live
    u_int8_t protocol;  //L4 protocol info
    u_int16_t header_checksum;  //error detection
    Ip sip_;
    Ip dip_;

    Ip sip() { return sip_; }
    Ip dip() { return dip_; }
};
#pragma pack(pop)

