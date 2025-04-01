#include "pch.h"

void GetAddressFromInterface(const char *interface_name, char *mac_addr, char *ip_addr)
{
    int socket_d = socket(AF_INET, SOCK_DGRAM, 0);  //udp socket open
    if(socket_d < 0)
    {
        printf("Failed to get mac address - socket\n");
        exit(1);
    }

    //check mac address of the network interface - ifr_hwaddr : sa_data
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);  //copy interface name
    int ret = ioctl(socket_d, SIOCGIFHWADDR, &ifr);  //read and store hardware address
    if(ret < 0)
    {
        printf("Failed to get mac address - ioctl\n");
        exit(1);
    }

    u_int8_t mac_addr_find[6];
    memcpy(mac_addr_find, ifr.ifr_hwaddr.sa_data, 6);  //copy mac address
    snprintf(mac_addr, 18,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr_find[0], mac_addr_find[1], mac_addr_find[2],
             mac_addr_find[3], mac_addr_find[4], mac_addr_find[5]);


    //check ip address of the network interface - ifr_addr : sockaddr_in.sin_addr
    ret = ioctl(socket_d, SIOCGIFADDR, &ifr);  //read and store ip address
    if(ret < 0)
    {
        printf("Failed to get ip address - ioctl\n");
        exit(1);
    }

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip_addr, inet_ntoa(ipaddr->sin_addr));  //converts IPv4 address stored in network byte order into a dotted string format.
    ip_addr[strlen(inet_ntoa(ipaddr->sin_addr))] = '\0';
}
