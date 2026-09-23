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


#define SEQ1 0
#define SEQ2 1
#define SEQ3 2
#define SEQ4 3
#define SEQ5 4
#define SEQ6 5

#define SRC_PORT_INIT 1000



char *target_IP;
char *OPEN_PORT;
char *CLOSED_PORT;


int match_tcp_probes(struct tcp_probe_res *tcp_probe_res, struct parsed_info *parsed_res, size_t num_probes) {
    if (tcp_probe_res == NULL || parsed_res == NULL || num_probes == 0) {
        fprintf(stderr, "Invalid arguments to match_tcp_probes\n");
        return 0;
    }

    for (size_t i = 0; i < num_probes; ++i) {
        for (size_t j = 0; j < num_probes; ++j) {
            if (tcp_probe_res[i].probe_sent.source_port == parsed_res[j].app_protocol.tcp_ap.dst_port &&
                tcp_probe_res[i].probe_sent.dest_port == parsed_res[j].app_protocol.tcp_ap.src_port) {
                tcp_probe_res[i].status = PROBE_RECEIVED;
                tcp_probe_res[i].response = parsed_res[i];
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
    printf("Closed port: %s\n", CLOSED_PORT);


    struct network net = {0};
    if (network_init(&net, "eth0", target_IP) != 0) {
        return EXIT_FAILURE;
    }


    struct tcp_probe_res tcp_probe_res[6] = {0};
    struct tcp_probe *tcp_probes = sequence_generation_TCP_spec(SRC_PORT_INIT, atoi(OPEN_PORT), target_IP);
    uint8_t *tcp_packets_t1[6] = {0};
    size_t tcp_packet_len[6] = {0};

    for (int i = 0; i < 6; i++) {
        tcp_probe_res[i].probe_id = i;
        tcp_probe_res[i].status = PROBE_NOT_SENT;
        tcp_probe_res[i].probe_sent = tcp_probes[i];
        tcp_probe_res[i].response = (struct parsed_info){0};

        tcp_packets_t1[i] = construct_TCP_packet(&tcp_probes[i], "172.25.0.230", &tcp_packet_len[i]);
        printf("Constructed SequenceTCP packet number %d of length: %lu bytes\n", i + 1, tcp_packet_len[i]);
    }

    for (int i = 0; i < 6; i++) {
        printf("Sending sequence TCP packet %d to: %s\n", i + 1, target_IP);
        tcp_probe_res[i].status = PROBE_NO_RESPONSE;
        tcp_probe_res[i].sent_at = (struct timespec){0};

        send_packet(&net, tcp_packets_t1[i], tcp_packet_len[i], target_IP);
        clock_gettime(CLOCK_MONOTONIC, &tcp_probe_res[i].sent_at);
        nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100 * 1000000,}, NULL);
    }

    printf("\n");

    struct parsed_info parsed_res[6] = {0};
    for (int i = 0; i < 6; i++) {
        receive_packet(&net, &parsed_res[i]);
    }    

    match_tcp_probes(tcp_probe_res, parsed_res, 6);

    
    // struct icmp_probe *icmp_probes = ICMPEchoProbeSpec(1000, atoi(OPEN_PORT), target_IP);
    // size_t icmp_packet_len = 0;
    // uint8_t *icmp_packet1 = constructICMPPacket(&icmp_probes[0], "172.25.0.230", &icmp_packet_len);
    // uint8_t *icmp_packet2 = constructICMPPacket(&icmp_probes[1], "172.25.0.230", &icmp_packet_len);


    return 0;
}

