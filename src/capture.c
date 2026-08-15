#include <stdio.h>
#include <pcap.h>
#include "../include/capture.h"

int list_interfaces(pcap_if_t **devices) {
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	int result = pcap_findalldevs(devices, errbuf);

	if (result == -1) {
		fprintf(stderr, "Error finding devices: %s\n", errbuf);
		return -1;
	}

	if (*devices == NULL) {
		printf("No network interfaces found.\n");
		return -1;
	}

	int index = 0;
	pcap_if_t *current = *devices;

  while (current != NULL) {
    printf("[%d] ", index);

    if (current->description != NULL) {
      printf("%s", current->description);
    }
    else {
      printf("No description");
    }

    printf("\n");
    printf("    Device: %s\n", current->name);

    current = current->next;
    index++;
    }

    return index;
}
	pcap_t *open_interface(
    const char *device_name,
    char *errbuf
) {
	int snaplen = 65535;
	int promiscuous = 1;
	int timeout_ms = 1000;

  pcap_t *handle = pcap_open_live(
    device_name,
    snaplen,
    promiscuous,
		timeout_ms,
    errbuf
  );

  if (handle == NULL) {
    return NULL;
  }

  return handle;
}

void close_capture(pcap_t *handle) {
	if (handle != NULL) {
		pcap_close(handle);
	}
}