#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <pcap.h>

#include "../include/ethernet.h"

#pragma pack(push, 1)
struct ethernet_header {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t ether_type;
};
#pragma pack(pop)

void analyze_ethernet(
    const u_char *packet,
    bpf_u_int32 caplen
) {
	if(caplen < 14) {
		printf("ERROR: packet's length is too small.\n");
		return;
	} 

	const struct ethernet_header *eth = (const struct ethernet_header *)packet;

  uint16_t type = ntohs(eth->ether_type);
  const char *protocol_name;

  switch(type) {
    case ETHERTYPE_IPV4: protocol_name = "IPv4"; break;
    case ETHERTYPE_ARP: protocol_name = "ARP";  break;
    case ETHERTYPE_IPV6: protocol_name = "IPv6"; break;
    default:     protocol_name = "Unknown"; break;
  }

	printf("Destination MAC: ");
  print_mac(eth->destination);
  printf("\nSource MAC: ");
  print_mac(eth->source);
  printf("\nProtocol: %s \n", protocol_name);
}

void print_mac(const u_char *mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}