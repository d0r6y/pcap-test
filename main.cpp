#include <libnet.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14


const struct libnet_ethernet_hdr *ethernet;
const struct libnet_ipv4_hdr *ip;
const struct libnet_tcp_hdr *tcp;
const u_char *payload;

uint8_t size_ip;
uint8_t size_tcp;

/*
 * Function that prints MAC Address
 * 
 * Logic
 * 1. Assigns input (packet Raw data) into predefined Ethernet Header Structure
 * 2. Get ethernet_shost, ethernet_dhost field (MAC Address)
 * 3. print
 */
void print_ethernet_header(const struct libnet_ethernet_hdr* eh){
	
	uint16_t ip_version = ntohs(eh->ether_type);

	if(ip_version != 0x0800){
		printf("IPv6 packet!!\n");
		return;
	}

	printf("\n------------------------------------------------\n");
	printf("               <Ethernet Header>               \n");
	printf("       Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		(eh->ether_dhost)[0],	
		(eh->ether_dhost)[1],
		(eh->ether_dhost)[2],
		(eh->ether_dhost)[3],
		(eh->ether_dhost)[4],
		(eh->ether_dhost)[5]);

	printf("       Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		(eh->ether_shost)[0],
		(eh->ether_shost)[1],
		(eh->ether_shost)[2],
		(eh->ether_shost)[3],
		(eh->ether_shost)[4],
		(eh->ether_shost)[5]);
	printf("------------------------------------------------\n");

};

/*
 * Function that prints IP Address
 * 
 * Logic
 * 1. Assigns input (packet Raw data) into predefined IP Header Structure
 * 2. Get ip_src_addr, ip_dst_addr field (IP Address)
 * 3. print
 */
 
 
void print_ip_header(const struct libnet_ipv4_hdr *iph){

	
	printf("                  <IP Header>               \n");
	printf("           SRC IP Addr [%s]\n",inet_ntoa(iph->ip_src));

	printf("          DST IP Addr [%s]\n", inet_ntoa(iph->ip_dst));
	printf("------------------------------------------------\n");
	
};

/*
 * Function that prints Port Number
 * 
 * Logic
 * 1. Assigns input (packet Raw data) into predefined TCP Header Structure
 * 2. Get tcp_src_port, tcp_dst_port field (Port Number)
 * 3. Since byte-order can affect the output, use ntohs() function in order to print the right answer whether my cpu is Little Endian or Big Endian
 * 4. print
 */
void print_tcp_header(const struct libnet_tcp_hdr *th){
	
	printf("                  <TCP Header>               \n");
	printf("                Src Port : %d\n", ntohs(th->th_sport));
	printf("                Dst Port : %d\n", ntohs(th->th_dport));
	printf("------------------------------------------------\n");

};

/*
 * Function that prints Data
 * 
 * Logic
 * 1. print input (packet Raw data) in hexa decimal value ( ~ 32 byte long )
 */
void print_payload (const unsigned char * packet){
	printf("                     <DATA>                   \n");
	
	int tmp = 32;
	int count = 0;
	while(tmp--){
		printf("%02x ", *packet++);
		if(++count%16 == 0){
			printf("\n");
		}
	}
	printf("================================================\n");
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	ethernet = (struct libnet_ethernet_hdr*)packet;
	
	ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
	
	size_ip = ip->ip_hl * 4;
	
	tcp = (struct libnet_tcp_hdr *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = tcp->th_off * 4;
	
	payload = (const u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	print_ethernet_header(ethernet);
	print_ip_header(ip);
	print_tcp_header(tcp);
	print_payload(payload);
	
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
	
	pcap_close(handle);
	return(0);
	
}
