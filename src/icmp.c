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

const char *icmp_type_name(uint8_t type);

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
	printf("ICMP \n");
	printf("--------------------------------------------------------------\n");
	printf("Type                     : %u(%s)\n", type, icmp_type_name(type));
	printf("Code                     : %u\n", code);
	printf("Checksum                 : %u\n", checksum);
}

const char *icmp_type_name(uint8_t type)
{
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY: return "Echo Reply";
				case ICMP_TYPE_DEST_UNREACHABLE: return "Destination Unreachable";
				case ICMP_TYPE_REDIRECT: return "Redirect";
				case ICMP_TYPE_ECHO_REQUEST: return "Echo Request";
				case ICMP_TYPE_TIME_EXCEEDED: return "Time Exceeded";
				default: return "Unknown";
		}
}