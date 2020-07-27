#pragma once
#include <libnet.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>


/*
 * Function that prints MAC Address
 */
 
void print_ethernet_header(const struct libnet_ethernet_hdr* eh);


/*
 * Function that prints IP Address
 * 
 * inet_ntoa() : transfers 32bit ip address data into human-read string
 */

void print_ip_header(const struct libnet_ipv4_hdr *iph);


/*
 * Function that prints TCP Port Number
 */
 
void print_tcp_header(const struct libnet_tcp_hdr *th);


/*
 * Function that prints PayloadData
 * 
 * Logic
 * -> print input (packet Raw data) in hexa decimal value ( ~ 16 byte long )
 */
 
void print_payload (const unsigned char * packet);


/*
 * Callback Func of the PCAP_LOOP
 *
 * 1. Assigns Raw Data into packet Structures
 * 2. Call print functions
 * 3. If TCP header is invalid, this is not TCP Packet
 */
 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
