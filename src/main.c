#include "packet.h"
#include "probes.h"
#include "network.h"
#include "matcher.h"
#include "fingerprint.h"
#include "structures.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h> 


char *target_IP;
char *OPEN_PORT;
char *CLOSED_PORT;

static bool matches_quoted_udp(const struct udp_probe *probe, const uint8_t *ip, size_t len, struct in_addr source_ip, struct in_addr target_ip) {
    if (ip == NULL || len < 20 ||
        (ip[0] >> 4) != 4 || ip[9] != IPPROTO_UDP) {
        return false;
    }

    size_t ihl = (ip[0] & 0x0Fu) * 4u;

    if (ihl < 20 || ihl > len || len - ihl < 8) {
        return false;
    }

    /* Reject noninitial fragments. */
    if ((ip[6] & 0x1Fu) != 0 || ip[7] != 0) {
        return false;
    }

    if (memcmp(ip + 12, &source_ip.s_addr, 4) != 0 ||
        memcmp(ip + 16, &target_ip.s_addr, 4) != 0) {
        return false;
    }

    const uint8_t *udp = ip + ihl;
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];

    return src_port == probe->source_port &&
           dst_port == probe->dest_port;
}

static bool response_matches_probe(const struct probe_result *probe, const struct parsed_info *response, struct in_addr source_ip) {
    struct in_addr target_ip;
    const char *target;

    switch (probe->probe_type) {
    case TCP_PROBE:
        if (response->ip_protocol != IPPROTO_TCP) {
            return false;
        }
        target = probe->probe_sent.tcp.dest_ip;
        break;
    case UDP_PROBE:
        if (response->ip_protocol != IPPROTO_ICMP ||
            response->app_protocol.icmp_ap.type != ICMP_DEST_UNREACH ||
            response->app_protocol.icmp_ap.code != ICMP_PORT_UNREACH) {
            return false;
        }
        target = probe->probe_sent.udp.dest_ip;
        break;
    case ICMP_PROBE:
        if (response->ip_protocol != IPPROTO_ICMP ||
            response->app_protocol.icmp_ap.type != ICMP_ECHOREPLY) {
            return false;
        }
        target = probe->probe_sent.icmp.dest_ip;
        break;

    default:
        return false; // UDP/U1 matching will be added separately
    }

    if (target == NULL ||
        inet_pton(AF_INET, target, &target_ip) != 1) {
        return false;
    }

    /* Response must travel from the target back to our source IP. */
    if (response->src_ip.s_addr != target_ip.s_addr ||
        response->dst_ip.s_addr != source_ip.s_addr) {
        return false;
    }

    switch (probe->probe_type) {
    case TCP_PROBE:
        return probe->probe_sent.tcp.source_port == response->app_protocol.tcp_ap.dst_port &&
            probe->probe_sent.tcp.dest_port == response->app_protocol.tcp_ap.src_port;
    case ICMP_PROBE:
        return probe->probe_sent.icmp.icmp_identifier == response->app_protocol.icmp_ap.header.echo.id &&
            probe->probe_sent.icmp.icmp_sequence == response->app_protocol.icmp_ap.header.echo.seq;
    case UDP_PROBE:
        return matches_quoted_udp(&probe->probe_sent.udp, response->app_protocol.icmp_ap.payload, response->app_protocol.icmp_ap.payload_len, source_ip, target_ip);
    default:
        return false;
    }
}


int match_tcp_probes(struct probe_result *probe_res, struct parsed_info *parsed_res, size_t probe_count, size_t response_count, struct in_addr source_ip) {
    if ((probe_res == NULL && probe_count != 0) ||
        (parsed_res == NULL && response_count != 0)) {
        fprintf(stderr, "Invalid arguments to match_probes\n");
        return -1;
    }

    int matched = 0;

    for (size_t j = 0; j < response_count; j++) {
        for (size_t i = 0; i < probe_count; i++) {
            if (probe_res[i].status != PROBE_NO_RESPONSE) {
                continue;
            }

            if (!response_matches_probe(&probe_res[i], &parsed_res[j], source_ip)) {
                continue;
            }

            probe_res[i].parsed_response = parsed_res[j];
            probe_res[i].status = PROBE_RECEIVED;

            // Clear the parsed_res[j] to avoid double matching
            parsed_res[j] = (struct parsed_info){0};

            matched++;
            break;
        }
    }

    return matched;
}


int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    if (argc != 3) {
        printf("Usage: %s <target_ip> <target_ports>\n", argv[0]);
        return 1;
    } 

    target_IP = argv[1];
    char src_IP[16] = "172.25.0.230";
    OPEN_PORT = strtok(argv[2], ","); 
    CLOSED_PORT = strtok(NULL, "");
    if (OPEN_PORT == NULL || CLOSED_PORT == NULL) {
        fprintf(stderr, "Error: Invalid target ports format. Please provide ports in the format <open_port>,<closed_port>\n");
        return 1;
    }

    printf("Target IP: %s\n", target_IP);
    printf("Open Port: %s\n", OPEN_PORT);
    printf("Closed port: %s\n\n", CLOSED_PORT);


    const uint16_t ecn_source_port = SRC_PORT_INIT + SEQ_PROBE_COUNT;
    const uint16_t t_first_source_port = ecn_source_port + 1;
    const uint16_t last_tcp_source_port = t_first_source_port + TX_COUNT - 1;
    const uint16_t udp_source_port = last_tcp_source_port + 1;

    struct network net = {0};
    if (network_init(&net, "eth0", src_IP, target_IP, SRC_PORT_INIT, last_tcp_source_port) != 0) {
        return EXIT_FAILURE;
    }

    struct probe_result probes_results[NUM_PROBES_SENT] = {0};

    // Sequence TCP Probes Construction
    struct tcp_probe *seq_tcp_probes = sequence_generation_TCP_spec(SRC_PORT_INIT, atoi(OPEN_PORT), target_IP);
    uint8_t *seq_tcp_packets[SEQ_PROBE_COUNT] = {0};
    size_t seq_tcp_packet_len[SEQ_PROBE_COUNT] = {0};
    if (seq_tcp_probes == NULL) {
        fprintf(stderr, "Failed to create sequence probe specifications\n");
        return EXIT_FAILURE;
    }

    // Sequence TCP Packet Construction
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        probes_results[i].probe_id = i;
        probes_results[i].status = PROBE_NOT_SENT;
        probes_results[i].probe_sent.tcp = seq_tcp_probes[i];
        probes_results[i].probe_type = TCP_PROBE;

        seq_tcp_packets[i] = construct_TCP_packet(seq_tcp_probes[i], src_IP, &seq_tcp_packet_len[i]);

        if (seq_tcp_packets[i] == NULL) {
            fprintf(stderr, "Failed to construct sequence probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        printf("Constructed SequenceTCP packet number %zu of length: %zu bytes\n", i + 1, seq_tcp_packet_len[i]);
    }

    // ICMP Echo Probes + Packet Construction
    struct icmp_probe *icmp_probes = ICMP_echo_probe_spec(target_IP);
    if (icmp_probes == NULL) {
        fprintf(stderr, "Failed to create ICMP probe specifications\n");
        return EXIT_FAILURE;
    }
    size_t icmp_packet_lens[2] = {0};
    uint8_t *icmp_packets[2] = {0};
    icmp_packets[0] = construct_ICMP_packet(icmp_probes[0], src_IP, &icmp_packet_lens[0]);
    icmp_packets[1] = construct_ICMP_packet(icmp_probes[1], src_IP, &icmp_packet_lens[1]);
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        if (icmp_packets[i] == NULL) {
            fprintf(stderr, "Failed to construct ICMP probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        probes_results[IE1 + i].probe_id = IE1 + i;
        probes_results[IE1 + i].status = PROBE_NOT_SENT;
        probes_results[IE1 + i].probe_sent.icmp = icmp_probes[i];
        probes_results[IE1 + i].probe_type = ICMP_PROBE;
        printf("Constructed ICMP packet number %zu of length: %zu bytes\n", i + 1, icmp_packet_lens[i]);
    }

    printf("\n");

    // Sequence TCP Packet Sending
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        printf("Sending sequence TCP packet %zu to: %s\n", i + 1, target_IP);
        probes_results[i].sent_at = (struct timespec){0};

        clock_gettime(CLOCK_MONOTONIC, &probes_results[i].sent_at);
        if (send_packet(&net, seq_tcp_packets[i], seq_tcp_packet_len[i], target_IP) != 0) {
            fprintf(stderr, "Failed to send probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        probes_results[i].status = PROBE_NO_RESPONSE;
        if (i + 1 < SEQ_PROBE_COUNT)
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100 * 1000000,}, NULL);
    }

    // ICMP Echo Packets Sending
    printf("Sending 2 ICMP Echo packets to: %s\n", target_IP);
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        probes_results[IE1 + i].sent_at = (struct timespec){0};
    
        clock_gettime(CLOCK_MONOTONIC, &probes_results[IE1 + i].sent_at);
        if (send_packet(&net, icmp_packets[i], icmp_packet_lens[i], target_IP) != 0) {
            fprintf(stderr, "Failed to send ICMP probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        probes_results[IE1 + i].status = PROBE_NO_RESPONSE;
    }

    printf("\n");

    // ECN TCP Probe + Packet Construction
    struct tcp_probe ecn_tcp_probe = tcp_ecn_probe_spec(ecn_source_port, atoi(OPEN_PORT), target_IP);
    size_t ecn_tcp_packet_len = 0;
    uint8_t *ecn_tcp_packet = construct_TCP_packet(ecn_tcp_probe, src_IP, &ecn_tcp_packet_len);
    probes_results[ECN].probe_id = ECN;
    probes_results[ECN].status = PROBE_NOT_SENT;
    probes_results[ECN].probe_sent.tcp = ecn_tcp_probe;
    probes_results[ECN].probe_type = TCP_PROBE;
    if (ecn_tcp_packet == NULL) {
        fprintf(stderr, "Failed to construct ECN TCP packet\n");
        return EXIT_FAILURE;
    }
    printf("Constructed ECN TCP packet of length: %zu bytes\n", ecn_tcp_packet_len);

    // ECN TCP Packet Sending
    printf("Sending ECN TCP packet to: %s\n", target_IP);
    probes_results[ECN].sent_at = (struct timespec){0};
    clock_gettime(CLOCK_MONOTONIC, &probes_results[ECN].sent_at);
    if (send_packet(&net, ecn_tcp_packet, ecn_tcp_packet_len, target_IP) != 0) {
        fprintf(stderr, "Failed to send ECN probe\n");
        return EXIT_FAILURE;
    }
    probes_results[ECN].status = PROBE_NO_RESPONSE;

    printf("\n");

    // T2-T7 TCP Probes + Packet Construction
    struct tcp_probe *t2_t7_tcp_probes = tcp_t_probes_spec(t_first_source_port, atoi(OPEN_PORT), atoi(CLOSED_PORT), target_IP);
    uint8_t *t2_t7_tcp_packets[TX_COUNT] = {0};
    size_t t2_t7_tcp_packet_len[TX_COUNT] = {0};
    if (t2_t7_tcp_probes == NULL) {
        fprintf(stderr, "Failed to create sequence probe specifications\n");
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < TX_COUNT; i++) {
        probes_results[T2 + i].probe_id = T2 + i;
        probes_results[T2 + i].status = PROBE_NOT_SENT;
        probes_results[T2 + i].probe_sent.tcp = t2_t7_tcp_probes[i];
        probes_results[T2 + i].probe_type = TCP_PROBE;

        t2_t7_tcp_packets[i] = construct_TCP_packet(t2_t7_tcp_probes[i], src_IP, &t2_t7_tcp_packet_len[i]);
        if (t2_t7_tcp_packets[i] == NULL) {
            fprintf(stderr, "Failed to construct sequence probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        printf("Constructed T%zu TCP packet of length: %zu bytes\n", i + 2, t2_t7_tcp_packet_len[i]);
    }

    // T2-T7 TCP Packet Sending
    for (size_t i = 0; i < TX_COUNT; i++) {
        printf("Sending T%zu TCP packet to: %s\n", i + 2, target_IP);
        probes_results[T2 + i].sent_at = (struct timespec){0};

        clock_gettime(CLOCK_MONOTONIC, &probes_results[T2 + i].sent_at);
        if (send_packet(&net, t2_t7_tcp_packets[i], t2_t7_tcp_packet_len[i], target_IP) != 0) {
            fprintf(stderr, "Failed to send T%zu probe\n", i + 2);
            return EXIT_FAILURE;
        }
        probes_results[T2 + i].status = PROBE_NO_RESPONSE;
    }   
    printf("\n");


    // UDP Probe + Packet Construction
    struct udp_probe udp_probe = udp_probe_spec(udp_source_port, atoi(CLOSED_PORT), target_IP);
    size_t udp_packet_len = 0;
    uint16_t udp_checksum = 0;
    uint8_t *udp_packet = construct_UDP_packet(udp_probe, src_IP, &udp_packet_len, &udp_checksum);
    udp_probe.udp_checksum = udp_checksum;
    probes_results[U1].probe_id = U1;
    probes_results[U1].status = PROBE_NOT_SENT;
    probes_results[U1].probe_sent.udp = udp_probe;
    probes_results[U1].probe_type = UDP_PROBE;
    if (udp_packet == NULL) {
        fprintf(stderr, "Failed to construct UDP packet\n");
        return EXIT_FAILURE;
    }
    printf("Constructed UDP packet of length: %zu bytes\n", udp_packet_len);


    // UDP Packet Sending
    printf("Sending UDP packet to: %s\n", target_IP);
    probes_results[U1].sent_at = (struct timespec){0};
    clock_gettime(CLOCK_MONOTONIC, &probes_results[U1].sent_at);
    if (send_packet(&net, udp_packet, udp_packet_len, target_IP) != 0) {
        fprintf(stderr, "Failed to send UDP probe\n");
        return EXIT_FAILURE;
    }
    probes_results[U1].status = PROBE_NO_RESPONSE;

    printf("\nAll probes sent. Waiting for responses...\n\n");


    // Receive and Match Responses
    struct in_addr source_address;
    if (inet_pton(AF_INET, src_IP, &source_address) != 1) {
        fprintf(stderr, "Invalid source IP\n");
        return EXIT_FAILURE;
    }

    /* Count probes successfully sent and still waiting for a response. */
    size_t pending_count = 0;
    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        if (probes_results[i].status == PROBE_NO_RESPONSE) {
            pending_count++;
        }
    }

    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        perror("clock_gettime");
        return EXIT_FAILURE;
    }

    const double receive_timeout_seconds = 3.0;
    size_t matched_count = 0;

    while (matched_count < pending_count) {
        // Check the deadline even when unrelated packets keep arriving 
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            perror("clock_gettime");
            return EXIT_FAILURE;
        }

        double elapsed = ((double)now.tv_sec - (double)started.tv_sec) +
                        ((double)now.tv_nsec - (double)started.tv_nsec) / 1e9;

        if (elapsed >= receive_timeout_seconds) {
            break;
        }

        struct parsed_info response = {0};
        int status = receive_packet(&net, &response);

        if (status == 0) {
            // No usable response currently available
            free_parsed_info(&response);
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000000},NULL);
            continue;
        }

        if (status < 0) {
            free_parsed_info(&response);
            fprintf(stderr, "Receiving stopped with status %d\n", status);
            return EXIT_FAILURE;
        }

        int matched = match_tcp_probes(probes_results, &response, NUM_PROBES_SENT, 1, source_address);

        // response is saved in the probes_results if matched, so we can free the 
        // parsed_info structure here to avoid memory leaks
        free_parsed_info(&response);

        if (matched < 0) {
            fprintf(stderr, "Response matching failed\n");
            return EXIT_FAILURE;
        }

        matched_count += (size_t)matched;
    }

    printf("Matched %zu of %zu pending probes\n", matched_count, pending_count);

    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        if (probes_results[i].status == PROBE_NO_RESPONSE) {
            printf("No response for probe at index %zu\n", i);
        }
    }
    printf("\n");


    // Fingerprint Calculation 
    char buffer[1024] = {0};
    generate_fingerprint_string(probes_results, buffer, sizeof(buffer));
    printf("Fingerprint string: \n%s\n", buffer);
    return 0;
}

