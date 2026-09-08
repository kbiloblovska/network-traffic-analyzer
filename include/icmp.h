#ifndef ICMP_H
#define ICMP_H

#include <pcap.h>

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

void analyze_icmp(
		const u_char *packet,
		bpf_u_int32 caplen
);

#endif 