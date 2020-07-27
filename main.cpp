#include <libnet.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define SIZE_ETHERNET 14

const struct libnet_ethernet_hdr *ethernet;
const struct libnet_ipv4_hdr *ip;
const struct libnet_tcp_hdr *tcp;
const u_char *payload;

u_int size_ip;
u_int size_tcp;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("caplen : %d\n", header->caplen);
	printf("len : %d\n", header->len);
	
	ethernet = (struct libnet_ethernet_hdr*)packet;
	
	ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
	
	size_ip = ip->ip_hl * 4;
	
	tcp = (struct libnet_tcp_hdr *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = tcp->th_off * 4;
	
	payload = (const u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	printf("\n%d %d", size_ip, size_tcp);
	
	printf("\n%s",payload);
}

int main(int argc, char *argv[]){
	
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	dev = argv[1];


	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	pcap_loop(handle, 10, got_packet, NULL);
	
	// ----------------------------
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	return(0);
	
}
