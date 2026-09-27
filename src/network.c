#include "network.h"


int network_init(struct network *net, char *interface_name, char *source_ip, char *target_ip, uint16_t first_tcp_source_port, uint16_t last_tcp_source_port, uint16_t udp_source_port) {
    if (net == NULL) {
        return -1; // Invalid argument
    }
    net->send_socket_fd = -1;
    net->pcap_handle = NULL;

    if (interface_name == NULL || source_ip == NULL ||
        target_ip == NULL ||
        first_tcp_source_port > last_tcp_source_port) {
        fprintf(stderr, "Invalid network_init arguments\n");
        return -1;
    }

    net->send_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (net->send_socket_fd < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    // Set the IP_HDRINCL option to tell the kernel that headers are included in the packet
    int optval = 1;
    if (setsockopt(net->send_socket_fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Failed to set IP_HDRINCL option");
        close(net->send_socket_fd);
        net->send_socket_fd = -1;
        return -1;
    }


    // set up libpcap for being ready to receive packets
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    net->pcap_handle = pcap_open_live(interface_name, 65535, 0, 100, errbuf);
    if (net->pcap_handle == NULL) {
        fprintf(stderr, "Failed to open capture on %s: %s\n", interface_name, errbuf);
        close(net->send_socket_fd);
        net->send_socket_fd = -1;
        return -1;
    }

    struct bpf_program filter;
    char filter_expr[512];

    int written = snprintf(
        filter_expr, sizeof(filter_expr),
        "ip and src host %s and dst host %s and "
        "((tcp and dst portrange %u-%u) or "
        "(udp and dst port %u) or "
        "(icmp and (icmp[0] = 0 or "
        "(icmp[0] = 3 and icmp[1] = 3))))",
        target_ip,
        source_ip,
        (unsigned int)first_tcp_source_port,
        (unsigned int)last_tcp_source_port,
        (unsigned int)udp_source_port
    );

    if (written < 0 || (size_t)written >= sizeof(filter_expr)) {
        fprintf(stderr, "Capture filter buffer is too small\n");
        fprintf(stderr, "Capture filter buffer is too small\n");

        pcap_close(net->pcap_handle);
        net->pcap_handle = NULL;

        close(net->send_socket_fd);
        net->send_socket_fd = -1;
        return -1;
    }

    if (pcap_compile(net->pcap_handle, &filter, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(net->pcap_handle));

        pcap_close(net->pcap_handle);
        net->pcap_handle = NULL;

        close(net->send_socket_fd);
        net->send_socket_fd = -1;
        return -1;
    }

    if (pcap_setfilter(net->pcap_handle, &filter) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(net->pcap_handle));

        pcap_freecode(&filter);

        pcap_close(net->pcap_handle);
        net->pcap_handle = NULL;

        close(net->send_socket_fd);
        net->send_socket_fd = -1;
        return -1;
    }

    pcap_freecode(&filter);

    if (pcap_setnonblock(net->pcap_handle, 1, errbuf) == -1) {
        fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);

        pcap_close(net->pcap_handle);
        net->pcap_handle = NULL;

        close(net->send_socket_fd);
        net->send_socket_fd = -1;
        return -1;
    }


    return 0; // Success
}

int send_packet(struct network *net, uint8_t *packet, size_t packet_len, char *target_ip) {
    struct sockaddr_in dest = {0};

    dest.sin_family = AF_INET;
    dest.sin_port = 0;

    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) != 1) {
        perror("Invalid destination address!");
        return -1;
    }

    ssize_t sent = 0;

    do {
        sent = sendto(net->send_socket_fd, packet, packet_len, 0, (struct sockaddr *)&dest, sizeof(dest));
    } while (sent == -1 && errno == EINTR);

    if (sent == -1) {
        perror("sendto");
        return -1;
    }

    if ((size_t)sent != packet_len) {
        fprintf(stderr, "Unexpected number of bytes sent\n");
        return -1;
    }

    return 0;

}

int receive_packet(struct network *net, struct parsed_info *parsed) {
    if (net == NULL || net->pcap_handle == NULL || parsed == NULL) {
        return -1;
    }

    int datalink = pcap_datalink(net->pcap_handle);
    if (datalink != DLT_EN10MB) {
        fprintf(stderr, "Unsupported data link type: %d\n", datalink);
        return -1;
    }

    struct pcap_pkthdr *header;
    const u_char *bytes;

    int status = pcap_next_ex(net->pcap_handle, &header, &bytes);
    if (status != 1) {
        return status; // 0 for timeout, -1 for error, -2 for EOF
    }

    printf("Captured %u bytes\n", header->caplen);

    return parse_packet(bytes, header, pcap_datalink(net->pcap_handle), parsed);
}