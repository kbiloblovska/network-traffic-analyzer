#ifndef APPLICATION_H
#define APPLICATION_H

#include <pcap.h>
#include <stdint.h>

void print_hex(
    const u_char *data,
    bpf_u_int32 length
);


void analyze_application_tcp(
    const u_char *payload,
    bpf_u_int32 payload_length,
    uint16_t source_port,
    uint16_t destination_port
);

void analyze_application_udp(
    const u_char *payload,
    bpf_u_int32 payload_length,
    uint16_t source_port,
    uint16_t destination_port
);

void analyze_application_icmp(
    const u_char *payload,
    bpf_u_int32 payload_length,
    uint16_t source_port,
    uint16_t destination_port
);

#endif