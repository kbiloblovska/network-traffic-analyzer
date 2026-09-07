#ifndef IPV4_H
#define IPV4_H

#include <pcap.h>

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP  6
#define IP_PROTOCOL_UDP  17

void analyze_ipv4(
    const u_char *packet,
    bpf_u_int32 caplen
);

#endif 