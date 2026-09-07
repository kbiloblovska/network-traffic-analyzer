#ifndef TCP_H
#define TCP_H

#include <pcap.h>

#define TH_FIN 0x01  // 0000 0001
#define TH_SYN 0x02  // 0000 0010
#define TH_RST 0x04  // 0000 0100
#define TH_PSH 0x08  // 0000 1000
#define TH_ACK 0x10  // 0001 0000
#define TH_URG 0x20  // 0010 0000
#define TH_ECE 0x40  // 0100 0000
#define TH_CWR 0x80  // 1000 0000

void analyze_tcp(
    const u_char *packet,
    bpf_u_int32 caplen
);

#endif