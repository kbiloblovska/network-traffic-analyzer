#ifndef ICMP_H
#define ICMP_H

#include <pcap.h>

void analyze_icmp(
		const u_char *packet,
		bpf_u_int32 caplen
);

#endif 