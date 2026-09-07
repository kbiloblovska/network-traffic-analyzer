#include <stdio.h>
#include <pcap.h>

#include "../include/capture.h"
#include "../include/ethernet.h"
#include "../include/ipv4.h"

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

void capture_packets(pcap_t *handle, int packets_count) {
  struct pcap_pkthdr *header = NULL;
  const u_char *packet = NULL;

  int packet_number = 0;

  printf("\nCapturing packets...\n");
  fflush(stdout);

  int link_type = pcap_datalink(handle);

  if (link_type != DLT_EN10MB) {
    printf("ERROR: Unsupported link type.\n");
    return;
  }
  while (packet_number < packets_count) {
    int result = pcap_next_ex(
      handle, 
      &header, 
      &packet
    );

    if (result == 1) {
      packet_number++;
      printf("\nPacket #%d\n", packet_number);
      printf("Captured length %u\n", header->caplen);
      printf("Original length %u\n", header->len);
      analyze_ethernet(packet, header->caplen);
      printf("\n");
      analyze_ipv4(packet + 14, header->caplen - 14);
      printf("\n");
    } else if (result == 0) {
      printf("\nTimeout occurred.\nNo packet was available yet.\n");
      continue;
    } else if (result == -1) {
      fprintf(stderr, "Error while capturing packet%s", pcap_geterr(handle));
      break;
    } else if (result == -2) {
      printf("End of packet capturing.\n");
      break;
    }
  }
  
  printf("Packet capture finished.\n");
}


void close_capture(pcap_t *handle) {
	if (handle != NULL) {
		pcap_close(handle);
	}
}