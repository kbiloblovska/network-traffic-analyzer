#ifndef UDP_H
#define UDP_H

#include <pcap.h>

void analyze_udp(
		const u_char *packet,
		bpf_u_int32 caplen
);

#endif 