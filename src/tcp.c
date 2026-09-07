#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <pcap.h>


#include "../include/tcp.h"

#pragma pack(push, 1)
struct tcp_header {
		uint16_t source_port;
		uint16_t destination_port;
		uint32_t sequence_number;
		uint32_t acknowledgment_number;
		uint8_t data_offset_reserved;
		uint8_t flags;
		uint16_t window_size;
		uint16_t checksum;
		uint16_t urgent_pointer;
};
#pragma pack(pop)

void print_tcp_flags(const struct tcp_header *tcp);

void analyze_tcp(
    const u_char *packet,
    bpf_u_int32 caplen
) {
	const struct tcp_header *tcp = (const struct tcp_header *)packet;

	if(caplen < 20) {
		printf("ERROR: packet's length is too small.\n");
		return;
	}

	uint16_t source_port = ntohs(tcp->source_port);
	uint16_t destination_port = ntohs(tcp->destination_port);
	uint32_t sequence_number = ntohl(tcp->sequence_number);
	uint32_t acknowledgment_number = ntohl(tcp->acknowledgment_number);
	uint8_t data_offset = tcp->data_offset_reserved >> 4;
	if (data_offset < 5) {
		printf("ERROR: Invalid data offset value.\n");
		return;
	}
	uint8_t headers_length = data_offset * 4;
	if (caplen < headers_length) {
		printf("ERROR: Packet length is less than the TCP header length.\n");
		return;
	}

	uint16_t window_size = ntohs(tcp->window_size);
	uint16_t checksum = ntohs(tcp->checksum);
	uint16_t urgent_pointer = ntohs(tcp->urgent_pointer);

	printf("\n");
	printf("TCP Header:\n");
	printf("Source Port: %u\n", source_port);
	printf("Destination Port: %u\n", destination_port);
	printf("Sequence Number: %u\n", sequence_number);
	printf("Acknowledgment Number: %u\n", acknowledgment_number);
	print_tcp_flags(tcp);
	printf("Window Size: %u\n", window_size);
	printf("Checksum: %u\n", checksum);
	printf("Urgent Pointer: %u\n", urgent_pointer);
}

void print_tcp_flags(const struct tcp_header *tcp) {
    uint8_t flags = tcp->flags;

    printf("Flags: [ ");

    if (flags & TH_SYN) printf("SYN ");
    if (flags & TH_ACK) printf("ACK ");
    if (flags & TH_FIN) printf("FIN ");
    if (flags & TH_RST) printf("RST ");
    if (flags & TH_PSH) printf("PSH ");
    if (flags & TH_URG) printf("URG ");
    if (flags & TH_ECE) printf("ECE ");
    if (flags & TH_CWR) printf("CWR ");

    printf("]\n");
}