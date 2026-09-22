#ifndef PROBES_H
#define PROBES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <stdio.h>

struct tcp_probe {
    char *dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t tcp_flags;
    uint16_t window_size;
    uint8_t tcp_options[40];
    size_t tcp_options_len;
};

struct icmp_probe {
    char *dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_identifier;
    uint16_t icmp_sequence;
    bool ip_DF;
    uint8_t ip_TOS;
    uint16_t ip_id;
    uint8_t *payload;
    size_t payload_len;
};

struct tcp_probe *sequenceGenerationTCPSpec(uint16_t source_port, uint16_t dest_port, char *dest_ip);
struct icmp_probe *ICMPEchoProbeSpec(uint16_t source_port, uint16_t dest_port, char *dest_ip);

#endif /* PROBES_H */