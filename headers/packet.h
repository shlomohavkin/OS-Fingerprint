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

struct parsed_info {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t ip_id;
    uint8_t ip_ttl;
    uint16_t ip_tot_length;
    uint8_t ip_hdr_length;
    uint16_t ip_fragoff; // flags + frag offset

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
            uint8_t payload_len;
            // uint8_t payload_exp; // expected payload length by header
        }tcp_ap;
        struct icmp_u {

        }icmp_ap;
        struct udp_u {

        }udp_ap;
    }app_protocol;
};




uint8_t *construct_TCP_packet(struct tcp_probe tcp_probe_spec, char *source_ip, size_t *packet_len);
uint8_t *construct_ICMP_packet(struct icmp_probe *icmp_probe_spec, char *source_ip, size_t *packet_len);
uint16_t calculate_checksum(uint8_t *data, size_t len);

struct parsed_info tcp_probe_parse(const u_char *bytes, struct pcap_pkthdr *header);

#endif /* PACKET_H */