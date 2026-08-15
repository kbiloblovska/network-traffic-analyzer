#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "../include/capture.h"

int main(void) {
	pcap_if_t *alldevs = NULL;

	printf("NETWORK TRAFFIC ANALYZER\n");
	
	int device_count = list_interfaces(&alldevs);
	if(device_count < 0) {
		return EXIT_FAILURE;
	}

	int selected_index = 0;

	printf("\nSelect interface: ");
	if (scanf("%d", &selected_index) != 1) {
    printf("Invalid input.\n");

    pcap_freealldevs(alldevs);

  	return EXIT_FAILURE;
  }

	if (selected_index < 0 ||
        selected_index >= device_count) {
    printf("Invalid interface number.\n");

    pcap_freealldevs(alldevs);

    return EXIT_FAILURE;
  }

	pcap_if_t *selected_device = alldevs;

  for (int i = 0; i < selected_index; i++) {
    selected_device = selected_device->next;
  }

	printf("\nSelected interface:\n");

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

	printf("\nInterface opened successfully!\n");

  capture_pakets(handle, 10);

	close_capture(handle);

  pcap_freealldevs(alldevs);

  printf("Capture session closed.\n");

  return EXIT_SUCCESS;
}