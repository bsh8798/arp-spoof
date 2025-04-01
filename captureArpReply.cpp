#include "pch.h"

void captureArpReply(pcap_t *pcap, Ip targetIp, char *mac)
{
    struct pcap_pkthdr *header;  //meta data, capture time, length ...
    const u_char *packet;  //packet data

    while(true)
    {
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0) continue;  //no packet
        if(res < 0)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            exit(1);
        }

        //find ARP packet
        //reinterpret packet's data as an EthHdr structure
        const auto *eth_hdr = reinterpret_cast<const EthHdr*>(packet);
        if(ntohs(eth_hdr->type_) == EthHdr::Arp)
        {
            const auto *arp_hdr = reinterpret_cast<const ArpHdr*>(packet + sizeof(EthHdr));
            if(ntohs(arp_hdr->op_) == ArpHdr::Reply && ntohl(arp_hdr->sip_) == targetIp)
            {
                Mac *src_mac = (Mac *)&arp_hdr->smac_;  //store mac addree

                snprintf(mac, 18,
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         src_mac->mac_[0], src_mac->mac_[1], src_mac->mac_[2],
                         src_mac->mac_[3], src_mac->mac_[4], src_mac->mac_[5]);
                return;
            }
        }
    }
}
