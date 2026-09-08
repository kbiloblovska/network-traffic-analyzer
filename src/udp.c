#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <pcap.h>

#include "../include/udp.h"

#pragma pack(push, 1)
struct udp_header {
		uint16_t source_port;
		uint16_t destination_port;
		uint16_t length;
		uint16_t checksum;
};
#pragma pack(pop)

void analyze_udp(
		const u_char *packet,
		bpf_u_int32 caplen
) {
	if(caplen < 8) {
		printf("ERROR: packet's length is too small.\n");
		return;
	}

	const struct udp_header *udp = (const struct udp_header *)packet;

	uint16_t source_port = ntohs(udp->source_port);
	uint16_t destination_port = ntohs(udp->destination_port);
	uint16_t length = ntohs(udp->length);
	if (caplen < length) {
		printf("ERROR: Packet length is less than the UDP length field.\n");
		return;
	}
	uint16_t checksum = ntohs(udp->checksum);

	printf("\n");
	printf("UDP \n");
	printf("--------------------------------------------------------------\n");
	printf("Source Port              : %u\n", source_port);
	printf("Destination Port         : %u\n", destination_port);
	printf("Length                   : %u\n", length);
	printf("Checksum                 : %u\n", checksum);
}