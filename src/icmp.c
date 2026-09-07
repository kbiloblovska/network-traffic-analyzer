#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <pcap.h>

#include "../include/icmp.h"

#pragma pack(push, 1)
struct icmp_header {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
};
#pragma pack(pop)

void analyze_icmp(
		const u_char *packet,
		bpf_u_int32 caplen
) {
	if(caplen < 8) {
		printf("ERROR: packet's length is too small.\n");
		return;
	}

	const struct icmp_header *icmp = (const struct icmp_header *)packet;

	uint8_t type = icmp->type;
	uint8_t code = icmp->code;
	uint16_t checksum = ntohs(icmp->checksum);

	printf("\n");
	printf("ICMP Header:\n");
	printf("Type: %u\n", type);
	printf("Code: %u\n", code);
	printf("Checksum: %u\n", checksum);
}