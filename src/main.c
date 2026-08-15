#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(void) {
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};

	printf("NETWORK TRAFFIC ANALYZER\n");
	printf("Npcap: %s\n\n", pcap_lib_version());
	
	int result = pcap_findalldevs(&alldevs, errbuf);
	
	if (result == -1) {
		fprintf(stderr, "Error finding devices: %s\n", errbuf);
		return 1;
	}

	printf("Available network interfaces: \n");

	int number = 0;

	for(pcap_if_t *dev = alldevs; 
			dev != NULL;
			dev = dev->next) {
				printf("DEVICE %d:\n", number);
        printf("  Name: %s\n", dev->name);

        if (dev->description != NULL) {
            printf("  Description: %s\n", dev->description);
        }
        printf("\n");

        number++;
			}

	printf("Total interfaces: %d\n", number);

	//checking if any interfaces were found
	if (number == 0) {
		printf("No network interfaces found.\n");
		pcap_freealldevs(alldevs);
		return 1;
	}
	printf("\n");
	//asking to choose an interface
	int choice = 0;
	printf("Enter interface number: ");
	scanf("%d", &choice);

	if(choice < 0 || choice >= number) {
		printf("Invalid interface number.\n");
		pcap_freealldevs(alldevs);
		return 1;
	}

	//looking for chosen interface
	pcap_if_t *dev = alldevs;
	for (int i = 0; i < choice; i++) {
		dev=dev->next;
	}
	printf("\nSelected interface: \n");
	printf("%s\n", dev->name);

	if (dev -> description != NULL) {
		printf("Description: %s\n", dev->description);
	}
	printf("\n");
	//opening network interface
	pcap_t *handle = pcap_open_live(
		dev ->name,
		65536,
		1,
		1000,
		errbuf
	);


	if (handle == NULL) {
		fprintf(stderr, "Error opening device: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return 1;
	}

	printf("Capture started...\n");
	printf("Waiting for packets...\n");

	pcap_freealldevs(alldevs);

	return 0;
}