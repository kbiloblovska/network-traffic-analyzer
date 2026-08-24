#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

void analyze_ethernet(
    const u_char *packet,
    bpf_u_int32 caplen
);

void print_mac(const u_char *mac);

#endif