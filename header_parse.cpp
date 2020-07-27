#include <libnet.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "header_parse.h"

// Ethernet header's size is fixed
#define SIZE_ETHERNET 14

// Define Packet Structures
const struct libnet_ethernet_hdr *ethernet;
const struct libnet_ipv4_hdr *ip;
const struct libnet_tcp_hdr *tcp;
const u_char *payload;

// Size of ip, tcp part
uint8_t size_ip;
uint8_t size_tcp;


/*
 * Function that prints MAC Address
 */
 
void print_ethernet_header(const struct libnet_ethernet_hdr* eh){
	
	printf("\n================================================\n");
	printf("               <Ethernet Header>               \n");
	printf("        Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		(eh->ether_shost)[0],
		(eh->ether_shost)[1],
		(eh->ether_shost)[2],
		(eh->ether_shost)[3],
		(eh->ether_shost)[4],
		(eh->ether_shost)[5]);
	printf("        Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		(eh->ether_dhost)[0],	
		(eh->ether_dhost)[1],
		(eh->ether_dhost)[2],
		(eh->ether_dhost)[3],
		(eh->ether_dhost)[4],
		(eh->ether_dhost)[5]);
	printf("------------------------------------------------\n");
};


/*
 * Function that prints IP Address
 * 
 * inet_ntoa() : transfers 32bit ip address data into human-read string
 */

void print_ip_header(const struct libnet_ipv4_hdr *iph){

	printf("                  <IP Header>               \n");
	printf("          SRC IP Addr [%s]\n",inet_ntoa(iph->ip_src));

	printf("          DST IP Addr [%s]\n",inet_ntoa(iph->ip_dst));
	printf("------------------------------------------------\n");
};


/*
 * Function that prints TCP Port Number
 */
 
void print_tcp_header(const struct libnet_tcp_hdr *th){
	
	printf("                  <TCP Header>               \n");
	printf("                Src Port : %d\n", ntohs(th->th_sport));
	printf("                Dst Port : %d\n", ntohs(th->th_dport));
	printf("------------------------------------------------\n");
};


/*
 * Function that prints PayloadData
 * 
 * Logic
 * -> print input (packet Raw data) in hexa decimal value ( ~ 16 byte long )
 */
 
void print_payload (const unsigned char * packet){
	
	printf("                     <DATA>                   \n");

	int tmp = 16;
	
	while(tmp--){
		printf("%02x ", *packet++);
	}
	
	printf("\n================================================\n\n");
};


/*
 * Callback Func of the PCAP_LOOP
 *
 * 1. Assigns Raw Data into packet Structures
 * 2. Call print functions
 * 3. If TCP header is invalid, this is not TCP Packet
 */
 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	ethernet = (struct libnet_ethernet_hdr*)packet;
	
	ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl * 4;
	
	tcp = (struct libnet_tcp_hdr *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = tcp->th_off * 4;
	
	// If input packet is not TCP packet
	if (size_tcp < 20) {
		printf("Not TCP Packet!!\n\n");
		return;
	}
	
	payload = (const u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	print_ethernet_header(ethernet);
	print_ip_header(ip);
	print_tcp_header(tcp);
	print_payload(payload);
}
