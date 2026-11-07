#ifndef PACKET_H
#define PACKET_H

#include "probes.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pcap.h>



/**
 * Structure to hold parsed information from a network packet.
 * This structure is used to store relevant fields from the IP header, 
 * as well as protocol-specific fields for TCP and ICMP packets.
*/
struct parsed_info {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t ip_id;
    uint8_t ip_ttl;
    uint16_t ip_tot_length;
    uint8_t ip_hdr_length;
    uint16_t ip_fragoff; // flags + frag offset
    uint8_t ip_protocol;

    union {
        struct tcp_u {
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq;
            uint32_t ack;
            uint16_t win_size;
            uint8_t flags;
            uint8_t offset;

            uint8_t reserved; // Reserved bit quirk test
            uint16_t urg_pointer; // Urgent pointer quirk test

            uint8_t *options;
            uint8_t options_len;

            // bool options_valid;
            bool timestamp_present;
            uint32_t tsval;
            uint32_t tsecr;

            uint8_t *payload;
            size_t payload_len;
        } tcp_ap;

        struct icmp_u {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;

            union {
                struct {
                    uint16_t id;
                    uint16_t seq;
                } echo;

                struct {
                    uint32_t unused;
                    uint16_t ip_checksum; // Checksum of the quoted IP header in ICMP payload
                } unreachable;
            } header;

            uint8_t *payload;
            size_t payload_len;
        } icmp_ap;
    }app_protocol;
};



/**
 * Constructs a raw TCP packet based on the provided TCP probe specifications and source IP address.
 * @param tcp_probe_spec The specifications for the TCP probe, 
 * including source/destination ports, sequence numbers, flags, 
 * window size, and TCP options. Which are created in the probe.c file.
 * @return A pointer to the constructed raw TCP packet, or NULL on failure. 
 */
uint8_t *construct_TCP_packet(struct tcp_probe tcp_probe_spec, char *source_ip, size_t *packet_len);


/**
 * Constructs a raw ICMP packet based on the provided ICMP probe specifications and source IP address.
 * @param icmp_probe_spec The specifications for the ICMP probe, including destination IP, ICMP type/code, 
 * identifier/sequence, and payload.
 * @return A pointer to the constructed raw ICMP packet, or NULL on failure. 
 */
uint8_t *construct_ICMP_packet(struct icmp_probe icmp_probe_spec, char *source_ip, size_t *packet_len);


/**
 * Constructs a raw UDP packet based on the provided UDP probe specifications and source IP address.
 * @param udp_probe_spec The specifications for the UDP probe, including source/destination ports, and payload.
 * @return A pointer to the constructed raw UDP packet, or NULL on failure. 
 */
uint8_t *construct_UDP_packet(struct udp_probe udp_probe_spec, char *source_ip, size_t *packet_len, uint16_t *udp_checksum);

/**
 * Calculates the checksum of the provided data.
 * @param data The data for which to calculate the checksum.
 * @param len The length of the data.
 * @return The calculated checksum.
 */
uint16_t calculate_checksum(const uint8_t *data, size_t len);

/**
 * Main function to parse a network packet and extract relevant information into a parsed_info structure.
 * This function handles fields from Ethernet,IPv4, TCP, UDP, and ICMP protocols.
 * @param bytes The raw packet data.
 * @param header The pcap packet header containing metadata about the packet.
 * @param datalink The datalink type of the packet (e.g., Ethernet).
 * @param parsed A pointer to a parsed_info structure where the extracted information will be stored.
 * @return 1 on successful parsing, 0 if the packet is not relevant, or -1 on error.
 */
int parse_packet(const u_char *bytes, const struct pcap_pkthdr *header, int datalink, struct parsed_info *parsed);

/**
 * Function to free the memory allocated for a parsed_info structure, 
 * including any dynamically allocated fields within it.
 */
void free_parsed_info(struct parsed_info *parsed);

#endif /* PACKET_H */