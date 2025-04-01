#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>  //socket
#include <sys/socket.h>  //socket
#include <net/if.h>  //ifreq
#include <sys/ioctl.h>  //ioctl
#include <arpa/inet.h>
#include <vector>
#include <thread>
#include <mutex>
#include <map>

#include "arphdr.h"
#include "ethhdr.h"
#include "iphdr.h"
#include "address.h"

extern std::map<Ip, Mac> macAddress;

void GetAddressFromInterface(const char *interface_name, char *mac_addr, char *ip_addr);
Mac getMacAddress(pcap_t *pcap, Mac attackerMac, Ip attackerIp, Ip targetIp, char *mac);
void arpRequest(pcap_t *pcap, Mac attackerMac, Ip attackerIp, Ip targetIp, char *mac);
void captureArpReply(pcap_t *pcap, Ip targetIp, char *mac);
void arpReplyAttack(pcap_t *pcap, Address address);
void repeatSpoof(pcap_t *pcap, std::vector<Address> &addressList);
