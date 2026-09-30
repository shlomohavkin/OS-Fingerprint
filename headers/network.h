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

int get_source_ip(const char *target_ip, char *source_ip);
int get_interface_for_ip(const char *source_ip, char *interface_name, size_t capacity);

int network_init(struct network *net, char *interface_name, char *source_ip, char *target_ip, uint16_t first_tcp_source_port, uint16_t last_tcp_source_port);

int send_packet(struct network *net, uint8_t *packet, size_t packet_len, char *target_ip);
int receive_packet(struct network *net, struct parsed_info *parsed);

#endif /* NETWORK_H */