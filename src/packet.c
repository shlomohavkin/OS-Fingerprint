#include "packet.h"

#define TCP_HEADER_SIZE 20
#define IP_HEADER_SIZE 20
#define ETHERNET_HEADER_SIZE 14


uint8_t *construct_TCP_packet(struct tcp_probe *tcp_probe_spec, char *source_ip, size_t *packet_len) {
    if (tcp_probe_spec == NULL || source_ip == NULL || packet_len == NULL) {
        perror("Invalid arguments to constructTCPPacket");
        return NULL; 
    }

    if (tcp_probe_spec->tcp_options_len > 40 || tcp_probe_spec->tcp_options_len % 4 != 0) {
        perror("TCP options length exceeds maximum allowed size or is not a multiple of 4");
        return NULL; 
    }

    if (packet_len != 0)
        *packet_len = 0;

    size_t tcp_len = sizeof(struct tcphdr) + tcp_probe_spec->tcp_options_len;
    size_t total_len = sizeof(struct iphdr) + tcp_len;

    struct tcphdr tcp = {0}; // tcp header 
    struct iphdr ip = {0}; // ip header

    
    tcp.source = htons(tcp_probe_spec->source_port); 
    tcp.dest = htons(tcp_probe_spec->dest_port);    
    tcp.seq = htonl(tcp_probe_spec->seq_num);       
    tcp.ack_seq = htonl(tcp_probe_spec->ack_num);       
    tcp.doff = tcp_len / 4; // Data offset 
    tcp.th_flags = tcp_probe_spec->tcp_flags; // TCP flags
    tcp.window = htons(tcp_probe_spec->window_size); // Window size
    tcp.check = 0;              // Checksum (to be calculated later)

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
        inet_pton(AF_INET, tcp_probe_spec->dest_ip, &ip.daddr) != 1) {
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
    memcpy(packet + sizeof(ip) + sizeof(tcp), tcp_probe_spec->tcp_options, tcp_probe_spec->tcp_options_len); // tcp options


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

uint8_t *construct_ICMP_packet(struct icmp_probe *icmp_probe_spec, char *source_ip, size_t *packet_len) {
    if (icmp_probe_spec == NULL || source_ip == NULL || packet_len == NULL ) {
        return NULL; // Invalid arguments
    }

    if (packet_len != 0)
        *packet_len = 0;

    struct icmphdr icmp = {0}; // ICMP header 
    struct iphdr ip = {0}; // IP header

    if (icmp_probe_spec->payload_len > UINT16_MAX - (sizeof(ip) + sizeof(icmp)))
        return NULL;

    size_t total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_probe_spec->payload_len;

    
    icmp.type = icmp_probe_spec->icmp_type; 
    icmp.code = icmp_probe_spec->icmp_code;    
    icmp.un.echo.id = htons(icmp_probe_spec->icmp_identifier);       
    icmp.un.echo.sequence = htons(icmp_probe_spec->icmp_sequence);       
    icmp.checksum = 0;              // Checksum (to be calculated later)

    ip.version = 4;            // IPv4
    ip.ihl = 5;                // Internet Header Length (5 * 4 = 20 bytes)
    ip.tos = icmp_probe_spec->ip_TOS;                // Type of Service
    ip.tot_len = htons((uint16_t)total_len); // Total length
    ip.id = htons(icmp_probe_spec->ip_id);      // Identification
    if (icmp_probe_spec->ip_DF) {
        ip.frag_off = htons(IP_DF); // Set the DF flag if specified
    }
    ip.ttl = 64;               // Time to Live
    ip.protocol = IPPROTO_ICMP; // Protocol (ICMP)
    ip.check = 0;              // Checksum (calculated automatically by the kernel)
    if (inet_pton(AF_INET, source_ip, &ip.saddr) != 1 ||
        inet_pton(AF_INET, icmp_probe_spec->dest_ip, &ip.daddr) != 1) {
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
    memcpy(packet + sizeof(ip) + sizeof(icmp), icmp_probe_spec->payload, icmp_probe_spec->payload_len); // payload

    uint16_t icmp_checksum = calculate_checksum((uint8_t *)(packet + sizeof(ip)), sizeof(icmp) + icmp_probe_spec->payload_len);
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


struct parsed_info tcp_probe_parse(const u_char *bytes, struct pcap_pkthdr *header) {
    if (bytes == NULL || header == NULL) {
        perror("Invalid arguments to tcp_prbe_parse");
        return (struct parsed_info){0};
    }

    if (header->caplen < 14) {
        return (struct parsed_info){0}; // unsupported ethernet header
    }

    uint16_t ether_type = ((uint16_t)bytes[12] << 8) | bytes[13];

    if (ether_type != 0x0800) { // IPv4
        return (struct parsed_info){0};  /* handles untagged IPv4 only. */
    }

    uint8_t *ip_hdr = bytes + 14;
    uint8_t *tcp_hdr = ip_hdr + IP_HEADER_SIZE;
    struct parsed_info parsed_res = {0};

    // IP HEADER PARSING
    memcpy(&parsed_res.src_ip.s_addr, ip_hdr + 12, 4);
    memcpy(&parsed_res.dst_ip.s_addr, ip_hdr + 16, 4);
    parsed_res.ip_id = ((uint16_t)ip_hdr[4] << 8) | ip_hdr[5];
    parsed_res.ip_ttl = ip_hdr[8];
    parsed_res.ip_tot_length = ((uint16_t)ip_hdr[2] << 8) | ip_hdr[3];
    parsed_res.ip_hdr_length = ((uint8_t)ip_hdr[0] & 0b00001111) * 4u;
    parsed_res.ip_fragoff = ((uint16_t)ip_hdr[6] << 8) | ip_hdr[7];

    // TCP HEADER PARSING
    parsed_res.app_protocol.tcp_ap.src_port = ((uint16_t)tcp_hdr[0] << 8) | tcp_hdr[1];
    parsed_res.app_protocol.tcp_ap.dst_port = ((uint16_t)tcp_hdr[2] << 8) | tcp_hdr[3];
    parsed_res.app_protocol.tcp_ap.seq = ((uint32_t)tcp_hdr[4] << 24) | 
                                        ((uint32_t)tcp_hdr[5] << 16) | 
                                        ((uint32_t)tcp_hdr[6] << 8) | 
                                        tcp_hdr[7];
    parsed_res.app_protocol.tcp_ap.ack = ((uint32_t)tcp_hdr[8] << 24) | 
                                        ((uint32_t)tcp_hdr[9] << 16) | 
                                        ((uint32_t)tcp_hdr[10] << 8) | 
                                        tcp_hdr[11];
    parsed_res.app_protocol.tcp_ap.win_size = ((uint16_t)tcp_hdr[14] << 8) | tcp_hdr[15];
    parsed_res.app_protocol.tcp_ap.flags = tcp_hdr[13];
    parsed_res.app_protocol.tcp_ap.offset = (uint8_t)tcp_hdr[12] >> 4;
    parsed_res.app_protocol.tcp_ap.reserved = (uint8_t)tcp_hdr[12] & 0b00001111; // Extract reserved bits
    parsed_res.app_protocol.tcp_ap.urg_pointer = ((uint16_t)tcp_hdr[18] << 8) | tcp_hdr[19];


    if (parsed_res.app_protocol.tcp_ap.offset * 4u > TCP_HEADER_SIZE) {
        parsed_res.app_protocol.tcp_ap.options_len = (parsed_res.app_protocol.tcp_ap.offset * 4u) - TCP_HEADER_SIZE;
        if (parsed_res.app_protocol.tcp_ap.options_len > 40) {
            perror("TCP options length exceeds maximum allowed size");
            return (struct parsed_info){0}; // Return an empty struct on failure
        }
        parsed_res.app_protocol.tcp_ap.options = malloc(parsed_res.app_protocol.tcp_ap.options_len);
        if (parsed_res.app_protocol.tcp_ap.options == NULL) {
            perror("Failed to allocate memory for TCP options");
            return (struct parsed_info){0}; // Return an empty struct on failure
        }
        memcpy(parsed_res.app_protocol.tcp_ap.options, tcp_hdr + TCP_HEADER_SIZE, parsed_res.app_protocol.tcp_ap.options_len);
        parsed_res.app_protocol.tcp_ap.timestamp_present = false;

        for (size_t i = 0; i < parsed_res.app_protocol.tcp_ap.options_len; ++i) {
            if (tcp_hdr[TCP_HEADER_SIZE + i] == TCPOPT_TIMESTAMP && i + 9 < parsed_res.app_protocol.tcp_ap.options_len) { // Timestamp option
                parsed_res.app_protocol.tcp_ap.timestamp_present = true;
                memcpy(&parsed_res.app_protocol.tcp_ap.tsval, tcp_hdr + TCP_HEADER_SIZE + i + 2, 4);
                memcpy(&parsed_res.app_protocol.tcp_ap.tsecr, tcp_hdr + TCP_HEADER_SIZE + i + 6, 4);
                break;
            }
        }
    } else {
        parsed_res.app_protocol.tcp_ap.options_len = 0;
        parsed_res.app_protocol.tcp_ap.timestamp_present = false;
    }



    parsed_res.app_protocol.tcp_ap.payload_len = parsed_res.ip_tot_length - (parsed_res.ip_hdr_length + parsed_res.app_protocol.tcp_ap.offset * 4u);
    if (parsed_res.app_protocol.tcp_ap.payload_len > 0) {
        parsed_res.app_protocol.tcp_ap.payload = malloc(parsed_res.app_protocol.tcp_ap.payload_len);
        if (parsed_res.app_protocol.tcp_ap.payload == NULL) {
            perror("Failed to allocate memory for TCP payload");
            return (struct parsed_info){0}; // Return an empty struct on failure
        }
        memcpy(parsed_res.app_protocol.tcp_ap.payload, tcp_hdr + parsed_res.app_protocol.tcp_ap.offset * 4u, parsed_res.app_protocol.tcp_ap.payload_len);
    }

    // print_test(parsed_res); // Debugging: Print the parsed information

    return parsed_res;
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
            printf("TSval: %u, TSecr: %u\n", ntohl(parsed_res.app_protocol.tcp_ap.tsval), ntohl(parsed_res.app_protocol.tcp_ap.tsecr));
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
        printf("TCP Payload Length: %u bytes\n", parsed_res.app_protocol.tcp_ap.payload_len);
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