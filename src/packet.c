#include "packet.h"

#define ETHERNET_HEADER_SIZE 14
#define IP_HEADER_SIZE       20
#define TCP_HEADER_SIZE      20
#define UDP_HEADER_SIZE       8
#define ICMP_HEADER_SIZE      8


uint8_t *construct_TCP_packet(struct tcp_probe tcp_probe_spec, char *source_ip, size_t *packet_len) {
    if (packet_len == NULL) {
        return NULL;
    }
    *packet_len = 0;

    if (source_ip == NULL) {
        perror("Invalid arguments to constructTCPPacket");
        return NULL; 
    }

    if (tcp_probe_spec.tcp_options_len > 40 || tcp_probe_spec.tcp_options_len % 4 != 0) {
        perror("TCP options length exceeds maximum allowed size or is not a multiple of 4");
        return NULL; 
    } 

    size_t tcp_len = sizeof(struct tcphdr) + tcp_probe_spec.tcp_options_len;
    size_t total_len = sizeof(struct iphdr) + tcp_len;

    struct tcphdr tcp = {0}; // tcp header 
    struct iphdr ip = {0}; // ip header

    
    tcp.source = htons(tcp_probe_spec.source_port); 
    tcp.dest = htons(tcp_probe_spec.dest_port);    
    tcp.seq = htonl(tcp_probe_spec.seq_num);       
    tcp.ack_seq = htonl(tcp_probe_spec.ack_num);       
    tcp.doff = tcp_len / 4; // Data offset 
    tcp.th_flags = tcp_probe_spec.tcp_flags; // TCP flags
    tcp.window = htons(tcp_probe_spec.window_size); // Window size
    tcp.check = 0;              // Checksum (to be calculated later)
    tcp.urg_ptr = htons(tcp_probe_spec.urgent_pointer); // Urgent pointer
    tcp.res1 = tcp_probe_spec.reseved_bit ? 0x08u : 0; // Reserved bit

    ip.version = 4;            // IPv4
    ip.ihl = 5;                // Internet Header Length (5 * 4 = 20 bytes)
    ip.tos = 0;                // Type of Service
    ip.tot_len = htons((uint16_t)total_len); // Total length
    ip.id = htons(54321);      // Identification
    ip.frag_off = 0;           // Fragment offset
    ip.ttl = 64;               // Time to Live
    ip.protocol = IPPROTO_TCP; // Protocol (TCP)
    ip.check = 0;              // Checksum (calculated automatically by the kernel)
    if (inet_pton(AF_INET, source_ip, &ip.saddr) != 1 ||
        inet_pton(AF_INET, tcp_probe_spec.dest_ip, &ip.daddr) != 1) {
        perror("inet_pton failed");
        exit(1);
    }

    uint8_t *packet = calloc(1, total_len); // Buffer to hold the packet
    if (packet == NULL) {
        perror("Failed to allocate memory for TCP packet");
        exit(EXIT_FAILURE);
    }

    memcpy(packet, &ip, sizeof(ip)); // ip header
    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp)); // tcp header
    memcpy(packet + sizeof(ip) + sizeof(tcp), tcp_probe_spec.tcp_options, tcp_probe_spec.tcp_options_len); // tcp options
       


    // CALCULATE TCP CHECKSUM
    uint8_t checksum_input[12 + 20 + 40] = {0}; // IPv4 Pseudo-header (12 Bytes) + TCP header (20 Bytes) + TCP options (40 Bytes)

    memcpy(checksum_input, &ip.saddr, 4); // Source IP
    memcpy(checksum_input + 4, &ip.daddr, 4); // Destination IP
    checksum_input[8] = 0; // Reserved
    checksum_input[9] = ip.protocol; // Protocol

    uint16_t tcp_length_net = htons((uint16_t)tcp_len);

    memcpy(checksum_input + 10, &tcp_length_net, 2); // TCP length
    memcpy(checksum_input + 12, packet + sizeof(ip), tcp_len); // TCP header + options

    tcp.check = htons(calculate_checksum(checksum_input, 12 + tcp_len));

    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp)); // Update the TCP header with the checksum

    *packet_len = total_len; 
    return packet; // Success
}

uint8_t *construct_ICMP_packet(struct icmp_probe icmp_probe_spec, char *source_ip, size_t *packet_len) {
    if (source_ip == NULL || packet_len == NULL ) {
        return NULL; // Invalid arguments
    }

    if (packet_len != 0)
        *packet_len = 0;

    struct icmphdr icmp = {0}; // ICMP header 
    struct iphdr ip = {0}; // IP header

    if (icmp_probe_spec.payload_len > UINT16_MAX - (sizeof(ip) + sizeof(icmp)))
        return NULL;

    size_t total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_probe_spec.payload_len;

    
    icmp.type = icmp_probe_spec.icmp_type; 
    icmp.code = icmp_probe_spec.icmp_code;    
    icmp.un.echo.id = htons(icmp_probe_spec.icmp_identifier);       
    icmp.un.echo.sequence = htons(icmp_probe_spec.icmp_sequence);       
    icmp.checksum = 0;              // Checksum (to be calculated later)

    ip.version = 4;            // IPv4
    ip.ihl = 5;                // Internet Header Length (5 * 4 = 20 bytes)
    ip.tos = icmp_probe_spec.ip_TOS;                // Type of Service
    ip.tot_len = htons((uint16_t)total_len); // Total length
    ip.id = htons(icmp_probe_spec.ip_id);      // Identification
    if (icmp_probe_spec.ip_DF) {
        ip.frag_off = htons(IP_DF); // Set the DF flag if specified
    }
    ip.ttl = 64;               // Time to Live
    ip.protocol = IPPROTO_ICMP; // Protocol (ICMP)
    ip.check = 0;              // Checksum (calculated automatically by the kernel)
    if (inet_pton(AF_INET, source_ip, &ip.saddr) != 1 ||
        inet_pton(AF_INET, icmp_probe_spec.dest_ip, &ip.daddr) != 1) {
        perror("inet_pton failed");
        exit(1);
    }


    uint8_t *packet = calloc(1, total_len); // Buffer to hold the packet
    if (packet == NULL) {
        perror("Failed to allocate memory for ICMP packet");
        return NULL;
    }

    memcpy(packet, &ip, sizeof(ip)); // IP header    
    memcpy(packet + sizeof(ip), &icmp, sizeof(icmp)); // ICMP header
    memcpy(packet + sizeof(ip) + sizeof(icmp), icmp_probe_spec.payload, icmp_probe_spec.payload_len); // payload

    uint16_t icmp_checksum = calculate_checksum((uint8_t *)(packet + sizeof(ip)), sizeof(icmp) + icmp_probe_spec.payload_len);
    icmp.checksum = htons(icmp_checksum);
    memcpy(packet + sizeof(ip), &icmp, sizeof(icmp)); // Update the ICMP
    
    *packet_len = total_len;
    return packet; // Success
}

uint16_t calculate_checksum(uint8_t *data, size_t len) {
    uint32_t sum = 0;


    // sum the 16-bit words
    while (len >= 2) {
        uint16_t word = ((uint16_t)data[0] << 8) | data[1];
        sum += word;

        // Keep the accumulator bounded, even for long inputs. 
        sum = (sum & 0xFFFFu) + (sum >> 16);

        data += 2;
        len -= 2;
    }

    // If there's a leftover byte, add it as well
    if (len == 1) {
        sum += (uint16_t)data[0] << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum; // Return one's complement
}

/* Read network-order bytes and return host-order integers. */
static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static int copy_bytes(uint8_t **destination, const uint8_t *source, size_t length) {
    *destination = NULL;
    if (length == 0) {
        return 1;
    }

    *destination = malloc(length);
    if (*destination == NULL) {
        return -1;
    }

    memcpy(*destination, source, length);
    return 1;
}

void free_parsed_info(struct parsed_info *parsed) {
    if (parsed == NULL) {
        return;
    }

    switch (parsed->ip_protocol) {
    case IPPROTO_TCP:
        free(parsed->app_protocol.tcp_ap.options);
        free(parsed->app_protocol.tcp_ap.payload);
        break;

    case IPPROTO_ICMP:
        free(parsed->app_protocol.icmp_ap.payload);
        break;

    case IPPROTO_UDP:
        free(parsed->app_protocol.udp_ap.payload);
        break;
    }

    *parsed = (struct parsed_info){0};
}

static int parse_tcp_response(const uint8_t *tcp, size_t segment_len, struct parsed_info *out) {
    if (segment_len < TCP_HEADER_SIZE) {
        return 0;
    }

    size_t header_len = (size_t)(tcp[12] >> 4) * 4u;

    if (header_len < TCP_HEADER_SIZE || header_len > segment_len) {
        return 0;
    }

    out->app_protocol.tcp_ap.src_port = read_u16(tcp);
    out->app_protocol.tcp_ap.dst_port = read_u16(tcp + 2);
    out->app_protocol.tcp_ap.seq = read_u32(tcp + 4);
    out->app_protocol.tcp_ap.ack = read_u32(tcp + 8);

    out->app_protocol.tcp_ap.offset = tcp[12] >> 4;
    out->app_protocol.tcp_ap.reserved = tcp[12] & 0x0Fu;
    out->app_protocol.tcp_ap.flags = tcp[13];
    out->app_protocol.tcp_ap.win_size = read_u16(tcp + 14);
    out->app_protocol.tcp_ap.urg_pointer = read_u16(tcp + 18);

    size_t options_len = header_len - TCP_HEADER_SIZE;
    const uint8_t *options = tcp + TCP_HEADER_SIZE;

    // Validate option boundaries and extract timestamps 
    for (size_t i = 0; i < options_len; ) {
        uint8_t kind = options[i];

        if (kind == TCPOPT_EOL) {
            break;
        }

        if (kind == TCPOPT_NOP) {
            i++;
            continue;
        }
        
        // Need both the kind and length bytes 
        if (options_len - i < 2) {
            return 0;
        }

        size_t length = options[i + 1];
        if (length < 2 || length > options_len - i) {
            return 0;
        }

        if ((kind == TCPOPT_MAXSEG && length != 4) ||
            (kind == TCPOPT_WINDOW && length != 3) ||
            (kind == TCPOPT_SACK_PERMITTED && length != 2) ||
            (kind == TCPOPT_TIMESTAMP && length != 10)) {
            return 0;
        }

        if (kind == TCPOPT_TIMESTAMP &&
            !out->app_protocol.tcp_ap.timestamp_present) {
            out->app_protocol.tcp_ap.tsval =
                read_u32(options + i + 2);

            out->app_protocol.tcp_ap.tsecr =
                read_u32(options + i + 6);

            out->app_protocol.tcp_ap.timestamp_present = true;
        }

        // Continue validating options after the timestamp too.
        i += length;
    }

    out->app_protocol.tcp_ap.options_len = (uint8_t)options_len;
    if (copy_bytes(&out->app_protocol.tcp_ap.options, options, options_len) < 0) {
        return -1;
    }

    size_t payload_len = segment_len - header_len;
    out->app_protocol.tcp_ap.payload_len = payload_len;
    if (copy_bytes(&out->app_protocol.tcp_ap.payload,
                   tcp + header_len, payload_len) < 0) {
        return -1;
    }

    return 1;
}

static int parse_icmp_response(const uint8_t *icmp, size_t message_len, struct parsed_info *out) {
    if (message_len < ICMP_HEADER_SIZE) {
        return 0;
    }

    out->app_protocol.icmp_ap.type = icmp[0];
    out->app_protocol.icmp_ap.code = icmp[1];
    out->app_protocol.icmp_ap.checksum = read_u16(icmp + 2);

    if (icmp[0] == ICMP_ECHOREPLY || icmp[0] == ICMP_ECHO) {
        out->app_protocol.icmp_ap.header.echo.id = read_u16(icmp + 4);
        out->app_protocol.icmp_ap.header.echo.seq = read_u16(icmp + 6);
    } else if (icmp[0] == ICMP_DEST_UNREACH) {
        /*
         * Save bytes 4–7 unchanged as a host-order integer.
         * Interpret as U1's unused field only for port unreachable.
         */
        // Save the unused field as a 32-bit integer in host byte order
        // This is U1's unused field
        out->app_protocol.icmp_ap.header.unreachable.unused = read_u32(icmp + 4);
    } else {
        return 0; // Other ICMP message types not implemented here
    }

    size_t payload_len = message_len - ICMP_HEADER_SIZE;
    out->app_protocol.icmp_ap.payload_len = payload_len;

    if (copy_bytes(&out->app_protocol.icmp_ap.payload, icmp + ICMP_HEADER_SIZE, payload_len) < 0) {
        return -1;
    }

    return 1;
}

// static int parse_udp_response(const uint8_t *udp, size_t available_len, struct parsed_info *out) {
//     if (available_len < UDP_HEADER_SIZE) {
//         return 0;
//     }

//     uint16_t udp_len = read_u16(udp + 4);

//     if (udp_len < UDP_HEADER_SIZE || udp_len > available_len) {
//         return 0;
//     }

//     out->app_protocol.udp_ap.src_port = read_u16(udp);
//     out->app_protocol.udp_ap.dst_port = read_u16(udp + 2);
//     out->app_protocol.udp_ap.length = udp_len;
//     out->app_protocol.udp_ap.checksum = read_u16(udp + 6);

//     size_t payload_len = (size_t)udp_len - UDP_HEADER_SIZE;
//     out->app_protocol.udp_ap.payload_len = payload_len;

//     if (copy_bytes(&out->app_protocol.udp_ap.payload,
//                    udp + UDP_HEADER_SIZE, payload_len) < 0) {
//         return -1;
//     }

//     return 1;
// }

int parse_packet(const u_char *bytes, const struct pcap_pkthdr *header, int datalink, struct parsed_info *parsed) {
    if (parsed == NULL) {
        return -1;
    }

    // the caller of the function needs to free the allocated memory in the parsed_info struct
    *parsed = (struct parsed_info){0};

    if (bytes == NULL || header == NULL) {
        return -1;
    }

    if (datalink != DLT_EN10MB || header->caplen < ETHERNET_HEADER_SIZE) {
        return 0;
    }

    if (read_u16(bytes + 12) != 0x0800u) {
        return 0; // Only untagged IPv4 Ethernet frames
    }

    size_t ip_len = header->caplen - ETHERNET_HEADER_SIZE;
    const uint8_t *ip = bytes + ETHERNET_HEADER_SIZE;

    if (ip_len < IP_HEADER_SIZE) {
        return 0;
    }

    size_t ip_header_len = (size_t)(ip[0] & 0x0Fu) * 4u;
    uint16_t ip_total_len = read_u16(ip + 2);

    if ((ip[0] >> 4) != 4 ||
        ip_header_len < IP_HEADER_SIZE ||
        ip_header_len > ip_len ||
        ip_total_len < ip_header_len ||
        ip_total_len > ip_len) {
        return 0;
    }

    uint16_t fragment = read_u16(ip + 6);

    if (fragment & 0x3FFFu) {
        return 0; // No fragment reassembly: MF flag or nonzero fragment offset 
    }

    struct parsed_info parsed_res = {0};

    memcpy(&parsed_res.src_ip.s_addr, ip + 12, 4);
    memcpy(&parsed_res.dst_ip.s_addr, ip + 16, 4);

    parsed_res.ip_id = read_u16(ip + 4);
    parsed_res.ip_ttl = ip[8];
    parsed_res.ip_protocol = ip[9];
    parsed_res.ip_tot_length = ip_total_len;
    parsed_res.ip_hdr_length = (uint8_t)ip_header_len;
    parsed_res.ip_fragoff = fragment;

    const uint8_t *protocol_header = ip + ip_header_len;
    size_t protocol_len = (size_t)ip_total_len - ip_header_len;

    int status = -1;

    switch (parsed_res.ip_protocol) {
    case IPPROTO_TCP:
        status = parse_tcp_response(protocol_header, protocol_len, &parsed_res);
        break;

    case IPPROTO_ICMP:
        status = parse_icmp_response(protocol_header, protocol_len, &parsed_res);
        break;

    case IPPROTO_UDP:
        // status = parse_udp_response(protocol_header, protocol_len, &parsed_res);
        break;

    default:
        return 0;
    }

    if (status != 1) {
        free_parsed_info(&parsed_res);
        return status;
    }

    *parsed = parsed_res;
    return 1;
}

void print_test(struct parsed_info parsed_res) {
    printf("Parsed TCP Packet Information:\n");
    printf("Source IP: %s\n", inet_ntoa(parsed_res.src_ip));
    printf("Destination IP: %s\n", inet_ntoa(parsed_res.dst_ip));
    printf("IP ID: %u\n", parsed_res.ip_id);
    printf("IP TTL: %u\n", parsed_res.ip_ttl);
    printf("IP Total Length: %u\n", parsed_res.ip_tot_length);
    printf("IP Header Length: %u\n", parsed_res.ip_hdr_length);
    printf("IP Fragment Offset + Flags: 0b%016b\n", parsed_res.ip_fragoff);

    printf("TCP Source Port: %u\n", parsed_res.app_protocol.tcp_ap.src_port);
    printf("TCP Destination Port: %u\n", parsed_res.app_protocol.tcp_ap.dst_port);
    printf("TCP Sequence Number: %u\n", parsed_res.app_protocol.tcp_ap.seq);
    printf("TCP Acknowledgment Number: %u\n", parsed_res.app_protocol.tcp_ap.ack);
    printf("TCP Window Size: %u\n", parsed_res.app_protocol.tcp_ap.win_size);
    printf("TCP Flags: 0x%02X\n", parsed_res.app_protocol.tcp_ap.flags);
    printf("TCP Header Length (Data Offset): %u bytes\n", parsed_res.app_protocol.tcp_ap.offset * 4u);
    printf("TCP Reserved Bits: 0x%02X\n", parsed_res.app_protocol.tcp_ap.reserved);
    printf("TCP Urgent Pointer: %u\n", parsed_res.app_protocol.tcp_ap.urg_pointer);

    if (parsed_res.app_protocol.tcp_ap.options_len > 0) {
        printf("TCP Options Length: %u bytes\n", parsed_res.app_protocol.tcp_ap.options_len);
        if (parsed_res.app_protocol.tcp_ap.timestamp_present) {
            printf("Timestamp Option Present:\n");
            printf("TSval: %u, TSecr: %u\n", parsed_res.app_protocol.tcp_ap.tsval, parsed_res.app_protocol.tcp_ap.tsecr);
        } else {
            printf("Timestamp Option Not Present.\n");
        }
        printf("TCP Options (Hex): ");
        for (size_t i = 0; i < parsed_res.app_protocol.tcp_ap.options_len; ++i) {
            printf("%02X ", parsed_res.app_protocol.tcp_ap.options[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    } else {
        printf("No TCP Options Present.\n");
    }

    if (parsed_res.app_protocol.tcp_ap.payload_len > 0) {
        printf("TCP Payload Length: %zu bytes\n", parsed_res.app_protocol.tcp_ap.payload_len);
        for (size_t i = 0; i < parsed_res.app_protocol.tcp_ap.payload_len; ++i) {
            printf("%02X ", parsed_res.app_protocol.tcp_ap.payload[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    } else {
        printf("No TCP Payload Present.\n");
    }
}