#include "pch.h"
\
#pragma pack(push, 1)
    struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void arpRequest(pcap_t *pcap, Mac attackerMac, Ip attackerIp, Ip targetIp, char *mac)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(attackerIp);
    packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        exit(1);
    }

    captureArpReply(pcap, targetIp, mac);
}
