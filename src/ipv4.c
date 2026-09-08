#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <pcap.h>

#include "../include/ipv4.h"
#include "../include/tcp.h"
#include "../include/udp.h"
#include "../include/icmp.h"

#pragma pack(push, 1)
struct ipv4_header
{
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t destination;
};
#pragma pack(pop)

void analyze_ipv4(
    const u_char *packet,
    bpf_u_int32 caplen
) {
	if(caplen < 20) {
		printf("ERROR: packet's length is too small.\n");
		return;
	}

	const struct ipv4_header *ip = (const struct ipv4_header *)packet;

	uint8_t version = ip->version_ihl >> 4;
	
	if (version != 4) {
		printf("ERROR: Not an IPv4 packet.\n");
		return;
	}

	uint8_t ihl = ip->version_ihl & 0x0F;
	if (ihl < 5) {
		printf("ERROR: Invalid IHL value.\n");
		return;
	}

	if (caplen < ihl * 4) {
		printf("ERROR: Packet length is less than the header length.\n");
		return;
	}

	uint16_t total_length = ntohs(ip->total_length);
	if (caplen < total_length) {
		printf("ERROR: Packet length is less than the total length field.\n");
		return;
	}

	uint16_t identification = ntohs(ip->identification);
	uint16_t flags_fragment_offset = ntohs(ip->flags_fragment_offset);

	uint8_t ttl = ip->ttl;
	uint8_t protocol = ip->protocol;

	const char *protocol_name;
	switch (protocol) {
		case IP_PROTOCOL_ICMP: protocol_name = "ICMP"; break;
		case IP_PROTOCOL_TCP:  protocol_name = "TCP"; break;
		case IP_PROTOCOL_UDP:  protocol_name = "UDP"; break;
		default:               protocol_name = "Unknown"; break;
	}

	uint16_t checksum = ntohs(ip->checksum);

	uint32_t source_ip = ntohl(ip->source);
	uint32_t dest_ip = ntohl(ip->destination);

	printf("\nIPv4\n");
	printf("--------------------------------------------------------------\n");
	printf("Version                  : %u\n", version);
	printf("IHL                      : %u (Header Length: %u bytes)\n", ihl, ihl * 4);
	printf("Total Length             : %u\n", total_length);
	printf("Identification           : %u\n", identification);
	printf("Flags and Fragment Offset: %u\n", flags_fragment_offset);
	printf("TTL                      : %u\n", ttl);
	printf("Protocol                 : %u (%s)\n", protocol, protocol_name);
	printf("Checksum                 : 0x%04X\n", checksum);
	printf("Source IP                : %u.%u.%u.%u\n", (source_ip >> 24) & 0xFF, (source_ip >> 16) & 0xFF, (source_ip >> 8) & 0xFF, source_ip & 0xFF);
	printf("Destination IP           : %u.%u.%u.%u\n", (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF, (dest_ip >> 8) & 0xFF, dest_ip & 0xFF);

	switch (protocol) {
		case IP_PROTOCOL_ICMP: protocol_name = "ICMP"; analyze_icmp(packet + ihl * 4, caplen - ihl * 4); break;
		case IP_PROTOCOL_TCP:  protocol_name = "TCP";  analyze_tcp(packet + ihl * 4, caplen - ihl * 4); break;
		case IP_PROTOCOL_UDP:  protocol_name = "UDP";  analyze_udp(packet + ihl * 4, caplen - ihl * 4); break;
		default:               protocol_name = "Unknown"; break;
	}
}