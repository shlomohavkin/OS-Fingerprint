#ifndef NETWORK_H
#define NETWORK_H

#include "packet.h"
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>


struct network {
    int send_socket_fd;
    pcap_t *pcap_handle;
};

/**
 * Function to determine the source IP address that would be used to reach a given target IP address.
 * @return 0 on success, -1 on failure.
 */
int get_source_ip(const char *target_ip, char *source_ip);

/**
 * Function to determine the network interface that would be used to reach a given source IP address.
 * @return 0 on success, -1 on failure.
 */
int get_interface_for_ip(const char *source_ip, char *interface_name, size_t capacity);

/**
 * Initialize the network for sending and receiving packets.
 * @param net Pointer to the network structure to be initialized.
 * @param first_tcp_source_port First TCP source port to filter received packets.
 * @param last_tcp_source_port Last TCP source port to filter received packets.
 * @return 0 on success, -1 on failure.
 */
int network_init(struct network *net, char *interface_name, char *source_ip, char *target_ip, uint16_t first_tcp_source_port, uint16_t last_tcp_source_port);

/**
 * Function to send a raw packet through the network.
 * @return 0 on success, -1 on failure.
 */
int send_packet(struct network *net, uint8_t *packet, size_t packet_len, char *target_ip);

/**
 * Function to receive a packet from the network using libpcap. 
 * After receiving the packet, it calls the parser to parse the 
 * packet and store the parsed information in the provided parsed_info structure.
 * @return 1 on success, 0 on timeout, -1 on error, -2 on EOF.
 */
int receive_packet(struct network *net, struct parsed_info *parsed);

#endif /* NETWORK_H */