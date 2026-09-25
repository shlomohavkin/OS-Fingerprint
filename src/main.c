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



#define NUM_PROBES_SENT (SEQ_PROBE_COUNT + 1 + 2) // 6 sequence probes + 1 ECN probe + 2 ICMP probes
#define ECN_INDEX SEQ_PROBE_COUNT


char *target_IP;
char *OPEN_PORT;
char *CLOSED_PORT;

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
        return
            probe->probe_sent.tcp.source_port ==
                response->app_protocol.tcp_ap.dst_port &&
            probe->probe_sent.tcp.dest_port ==
                response->app_protocol.tcp_ap.src_port;

    case ICMP_PROBE:
        return
            probe->probe_sent.icmp.icmp_identifier ==
                response->app_protocol.icmp_ap.header.echo.id &&
            probe->probe_sent.icmp.icmp_sequence ==
                response->app_protocol.icmp_ap.header.echo.seq;

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


int main(int argc, char **argv)
{
    srand((unsigned)time(NULL));

    if (argc < 3 || argc > 3) {
        printf("Usage: %s <target_ip> <target_ports>\n", argv[0]);
        return 1;
    } 

    target_IP = argv[1];
    char src_IP[16] = "172.25.0.230";
    OPEN_PORT = strtok(argv[2], ","); 
    CLOSED_PORT = strtok(NULL, "");
    if (OPEN_PORT == NULL || CLOSED_PORT == NULL) {
        printf("Error: Invalid target ports format. Please provide ports in the format <open_port>,<closed_port>\n");
        return 1;
    }

    printf("Target IP: %s\n", target_IP);
    printf("Open Port: %s\n", OPEN_PORT);
    printf("Closed port: %s\n\n", CLOSED_PORT);


    struct network net = {0};
    if (network_init(&net, "eth0", target_IP) != 0) {
        return EXIT_FAILURE;
    }

    struct probe_result probes_results[NUM_PROBES_SENT] = {0};

    // Sequence TCP Probes Construction
    struct tcp_probe *seq_tcp_probes = sequence_generation_TCP_spec(SRC_PORT_INIT, atoi(OPEN_PORT), target_IP);
    uint8_t *seq_tcp_packets[6] = {0};
    size_t seq_tcp_packet_len[6] = {0};
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
    size_t icmp_packet_lens[2] = {0};
    uint8_t *icmp_packets[2] = {0};
    icmp_packets[0] = construct_ICMP_packet(icmp_probes[0], src_IP, &icmp_packet_lens[0]);
    icmp_packets[1] = construct_ICMP_packet(icmp_probes[1], src_IP, &icmp_packet_lens[1]);
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        probes_results[IE1 + i].probe_id = IE1 + i;
        probes_results[IE1 + i].status = PROBE_NOT_SENT;
        probes_results[IE1 + i].probe_sent.icmp = icmp_probes[i];
        probes_results[IE1 + i].probe_type = ICMP_PROBE;
    }

    // ECN TCP Probe + Packet Construction
    struct tcp_probe ecn_tcp_probe = tcp_ecn_probe_spec(SRC_PORT_INIT + ECN_INDEX, atoi(OPEN_PORT), target_IP);
    size_t ecn_tcp_packet_len = 0;
    uint8_t *ecn_tcp_packet = construct_TCP_packet(ecn_tcp_probe, src_IP, &ecn_tcp_packet_len);
    probes_results[ECN].probe_id = ECN;
    probes_results[ECN].status = PROBE_NOT_SENT;
    probes_results[ECN].probe_sent.tcp = ecn_tcp_probe;
    probes_results[ECN].probe_type = TCP_PROBE;

    printf("\n");

    // Sequence TCP Packet Sending
    for (size_t i = 0; i < 6; i++) {
        printf("Sending sequence TCP packet %zu to: %s\n", i + 1, target_IP);
        probes_results[i].status = PROBE_NO_RESPONSE;
        probes_results[i].sent_at = (struct timespec){0};

        clock_gettime(CLOCK_MONOTONIC, &probes_results[i].sent_at);
        if (send_packet(&net, seq_tcp_packets[i], seq_tcp_packet_len[i], target_IP) != 0) {
            fprintf(stderr, "Failed to send probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        probes_results[i].probe_sent.tcp = seq_tcp_probes[i];
        if (i < 5)
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100 * 1000000,}, NULL);
    }

    // ICMP Echo Packets Sending
    printf("Sending 2 ICMP Echo packets to: %s\n", target_IP);
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        probes_results[IE1 + i].status = PROBE_NO_RESPONSE;
        probes_results[IE1 + i].sent_at = (struct timespec){0};

        clock_gettime(CLOCK_MONOTONIC, &probes_results[IE1 + i].sent_at);
        if (send_packet(&net, icmp_packets[i], icmp_packet_lens[i], target_IP) != 0) {
            fprintf(stderr, "Failed to send ICMP probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        probes_results[IE1 + i].probe_sent.icmp = icmp_probes[i];
    }

    // ECN TCP Packet Sending
    printf("Sending ECN TCP packet to: %s\n", target_IP);
    probes_results[ECN].status = PROBE_NO_RESPONSE;
    probes_results[ECN].sent_at = (struct timespec){0};
    clock_gettime(CLOCK_MONOTONIC, &probes_results[ECN].sent_at);
    if (send_packet(&net, ecn_tcp_packet, ecn_tcp_packet_len, target_IP) != 0) {
        fprintf(stderr, "Failed to send ECN probe\n");
        return EXIT_FAILURE;
    }
    probes_results[ECN].probe_sent.tcp = ecn_tcp_probe;



    printf("\n");



    struct parsed_info parsed_res[NUM_PROBES_SENT] = {0};
    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        receive_packet(&net, &parsed_res[i]);
    }    

    // for now the number of probes sent and received is the same, 
    // but this can be changed in the future if needed
    match_tcp_probes(probes_results, parsed_res, NUM_PROBES_SENT, NUM_PROBES_SENT, (struct in_addr){.s_addr = inet_addr(src_IP)}); 

    
    struct os_fingerprint fingerprint = calculate_os_fingerprint(probes_results);
    if (!fingerprint.valid) {
        fprintf(stderr, "Fingerprint calculation failed\n");
        return EXIT_FAILURE;
    }



    return 0;
}

