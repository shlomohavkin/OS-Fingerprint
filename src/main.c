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




#define NUM_PROBES_SENT 7


char *target_IP;
char *OPEN_PORT;
char *CLOSED_PORT;


int match_tcp_probes(struct tcp_probe_res *tcp_probe_res, struct parsed_info *parsed_res, size_t probe_count, size_t response_count) {
    if (tcp_probe_res == NULL || parsed_res == NULL || probe_count == 0 || response_count == 0) {
        fprintf(stderr, "Invalid arguments to match_tcp_probes\n");
        return 0;
    }

    for (size_t i = 0; i < probe_count; ++i) {
        for (size_t j = 0; j < response_count; ++j) {
            if (tcp_probe_res[i].probe_sent.source_port == parsed_res[j].app_protocol.tcp_ap.dst_port &&
                tcp_probe_res[i].probe_sent.dest_port == parsed_res[j].app_protocol.tcp_ap.src_port) {
                tcp_probe_res[i].status = PROBE_RECEIVED;
                tcp_probe_res[i].parsed_response = parsed_res[j];
                break;
            } 
        }
    }

    return 1;
}


int main(int argc, char **argv)
{
    srand((unsigned)time(NULL));

    if (argc < 3 || argc > 3) {
        printf("Usage: %s <target_ip> <target_ports>\n", argv[0]);
        return 1;
    } 

    target_IP = argv[1];
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

    struct tcp_probe_res tcp_probes_res[NUM_PROBES_SENT] = {0};

    // Sequence TCP Probes Construction
    struct tcp_probe *seq_tcp_probes = sequence_generation_TCP_spec(SRC_PORT_INIT, atoi(OPEN_PORT), target_IP);
    uint8_t *seq_tcp_packets[6] = {0};
    size_t seq_tcp_packet_len[6] = {0};
    if (seq_tcp_probes == NULL) {
        fprintf(stderr, "Failed to create sequence probe specifications\n");
        return EXIT_FAILURE;
    }

    // ECN TCP Probe + Packet Construction
    struct tcp_probe ecn_tcp_probe = tcp_ecn_probe_spec(SRC_PORT_INIT + 6, atoi(OPEN_PORT), target_IP);
    size_t ecn_tcp_packet_len = 0;
    uint8_t *ecn_tcp_packet = construct_TCP_packet(ecn_tcp_probe, "172.25.0.230", &ecn_tcp_packet_len);
    tcp_probes_res[ECN].probe_id = ECN;
    tcp_probes_res[ECN].status = PROBE_NOT_SENT;
    tcp_probes_res[ECN].probe_sent = ecn_tcp_probe;

    // Sequence TCP Packet Construction + Res Structure Init
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        tcp_probes_res[i].probe_id = i;
        tcp_probes_res[i].status = PROBE_NOT_SENT;
        tcp_probes_res[i].probe_sent = seq_tcp_probes[i];

        seq_tcp_packets[i] = construct_TCP_packet(seq_tcp_probes[i], "172.25.0.230", &seq_tcp_packet_len[i]);

        if (seq_tcp_packets[i] == NULL) {
            fprintf(stderr, "Failed to construct sequence probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        printf("Constructed SequenceTCP packet number %zu of length: %zu bytes\n", i + 1, seq_tcp_packet_len[i]);
    }

    printf("\n");

    // Sequence TCP Packet Sending
    for (size_t i = 0; i < 6; i++) {
        printf("Sending sequence TCP packet %zu to: %s\n", i + 1, target_IP);
        tcp_probes_res[i].status = PROBE_NO_RESPONSE;
        tcp_probes_res[i].sent_at = (struct timespec){0};

        clock_gettime(CLOCK_MONOTONIC, &tcp_probes_res[i].sent_at);
        if (send_packet(&net, seq_tcp_packets[i], seq_tcp_packet_len[i], target_IP) != 0) {
            fprintf(stderr, "Failed to send probe %zu\n", i + 1);
            return EXIT_FAILURE;
        }
        tcp_probes_res[i].probe_sent = seq_tcp_probes[i];
        nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100 * 1000000,}, NULL);
    }

    // ECN TCP Packet Sending
    printf("Sending ECN TCP packet to: %s\n", target_IP);
    tcp_probes_res[ECN].status = PROBE_NO_RESPONSE;
    tcp_probes_res[ECN].sent_at = (struct timespec){0};
    clock_gettime(CLOCK_MONOTONIC, &tcp_probes_res[ECN].sent_at);
    if (send_packet(&net, ecn_tcp_packet, ecn_tcp_packet_len, target_IP) != 0) {
        fprintf(stderr, "Failed to send ECN probe\n");
        return EXIT_FAILURE;
    }
    tcp_probes_res[ECN].probe_sent = ecn_tcp_probe;

    printf("\n");

    struct parsed_info parsed_res[NUM_PROBES_SENT] = {0};
    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        receive_packet(&net, &parsed_res[i]);
    }    

    match_tcp_probes(tcp_probes_res, parsed_res, NUM_PROBES_SENT, NUM_PROBES_SENT); // for npw the number of probes sent and received is the same, 
                                                                                    // but this can be changed in the future if needed

    
    struct os_fingerprint fingerprint = calculate_os_fingerprint(tcp_probes_res);
    if (!fingerprint.valid) {
        fprintf(stderr, "Fingerprint calculation failed\n");
        return EXIT_FAILURE;
    }
    
    // struct icmp_probe *icmp_probes = ICMPEchoProbeSpec(1000, atoi(OPEN_PORT), target_IP);
    // size_t icmp_packet_len = 0;
    // uint8_t *icmp_packet1 = constructICMPPacket(&icmp_probes[0], "172.25.0.230", &icmp_packet_len);
    // uint8_t *icmp_packet2 = constructICMPPacket(&icmp_probes[1], "172.25.0.230", &icmp_packet_len);


    return 0;
}

