#include <libnet.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h> 
#include <arpa/inet.h> // for ntohl func
#include "header_parse.h"

int main(int argc, char *argv[]){
	
	pcap_t *handle;			/* Session handle */
	char *dev;				/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	
	bpf_u_int32 mask;			/* Our netmask */
	bpf_u_int32 net;			/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */

	dev = argv[1];

	// Find the properties for the device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// Open the session in promiscuous mode
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// Loop, and capture packets until error occurs
	pcap_loop(handle, -1, got_packet, NULL);

	// Close pcap handle
	pcap_close(handle);
	
	return(0);
}
