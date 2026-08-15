#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

#define MAX_INTERFACES 64

int list_interfaces(pcap_if_t **devices);

pcap_t *open_interface(
    const char *device_name,
    char *errbuf
);

void close_capture(pcap_t *handle);

#endif