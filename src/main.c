#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "../include/capture.h"
#include "../include/ethernet.h"
#include "../include/ipv4.h"

int main(void) {
	pcap_if_t *alldevs = NULL;

	printf("-------------------NETWORK TRAFFIC ANALYZER-------------------\n");
  printf("==============================================================\n");
	
	int device_count = list_interfaces(&alldevs);
	if(device_count < 0) {
		return EXIT_FAILURE;
	}

	int selected_index = 0;
  printf("--------------------------------------------------------------\n");
	printf("Select interface: ");
	if (scanf("%d", &selected_index) != 1) {
    printf("!!INVALID INPUT!!\n");

    pcap_freealldevs(alldevs);

  	return EXIT_FAILURE;
  }

	if (selected_index < 0 ||
        selected_index >= device_count) {
    printf("!!INVALID INTERFACE NUMBER!!\n");

    pcap_freealldevs(alldevs);

    return EXIT_FAILURE;
  }

	pcap_if_t *selected_device = alldevs;

  for (int i = 0; i < selected_index; i++) {
    selected_device = selected_device->next;
  }
  printf("--------------------------------------------------------------\n");
  printf("Selected interface: %s\n", selected_device->name);

  if (selected_device->description != NULL) {
    printf("Description: %s\n", selected_device->description);
  }

  printf("Device: %s\n", selected_device->name);

	char errbuf[PCAP_ERRBUF_SIZE] = {0};

  pcap_t *handle = open_interface( selected_device->name,
        errbuf
  );
 	
	if (handle == NULL) {
    fprintf(stderr, "Could not open interface:\n%s\n", errbuf);

    pcap_freealldevs(alldevs);

    return EXIT_FAILURE;
  } 
  printf("--------------------------------------------------------------\n");
	printf("Interface opened successfully!\n");

  capture_packets(handle, 10);

	close_capture(handle);

  pcap_freealldevs(alldevs);

  printf("Capture session closed.\n");

  return EXIT_SUCCESS;
}