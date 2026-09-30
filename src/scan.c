#include "packet.h"
#include "probes.h"
#include "probe_matcher.h"
#include "scan.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**
 * Store the probes specification and construct the packet for a specific 
 * TCP probe. 
 * @return 0 on success, -1 on failure.
 */
static int prepare_tcp_probe(struct scan_state *scan, const struct scan_config *config, size_t index, struct tcp_probe spec) {
    struct probe_result *result = &scan->results[index];
    struct probe_packet *packet = &scan->packets[index];

    result->probe_id = index;
    result->status = PROBE_NOT_SENT;
    result->probe_type = TCP_PROBE;
    result->probe_sent.tcp = spec;

    packet->data = construct_TCP_packet(spec, config->source_ip, &packet->length);
    if (packet->data == NULL) {
        fprintf(stderr, "Failed to construct TCP probe at index %zu\n", index);
        return -1;
    }
    return 0;
}

/**
 * Store the sequence probes specification and construct the packets for the sequence TCP probes.
 * @return 0 on success, -1 on failure.
 */
static int prepare_sequence_probes(struct scan_state *scan, const struct scan_config *config) {
    struct tcp_probe *specs = sequence_generation_TCP_spec(config->first_source_port, config->open_port, config->target_ip);
    if (specs == NULL) {
        fprintf(stderr, "Failed to create sequence probe specifications\n");
        return -1;
    }

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (prepare_tcp_probe(scan, config, i, specs[i]) < 0) {
            free(specs);
            return -1;
        }
        printf("Constructed Sequence TCP packet number %zu of length: %zu bytes\n", i + 1, scan->packets[i].length);
    }

    /* TCP options are dynamically allocated in sequence_generation_TCP_spec, 
    so we can free the specs array now. and they are still saved in the scan state structure */
    free(specs);
    return 0;
}


/**
 * Store the probes specification and construct the packet for the ICMP echo probes.
 * @return 0 on success, -1 on failure.
 */
static int prepare_ie_probes(struct scan_state *scan, const struct scan_config *config) {
    // Probe Construction 
    struct icmp_probe *specs = ICMP_echo_probe_spec(config->target_ip);
    if (specs == NULL) {
        fprintf(stderr, "Failed to create ICMP probe specifications\n");
        return -1;
    }

    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        struct probe_result *result = &scan->results[IE1 + i];
        result->probe_id = IE1 + i;
        result->status = PROBE_NOT_SENT;
        result->probe_type = ICMP_PROBE;
        result->probe_sent.icmp = specs[i];
    }
    free(specs); /* Payloads now belong to scan->results. */

    // Packet Construction
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        struct probe_packet *packet = &scan->packets[IE1 + i];
        packet->data = construct_ICMP_packet(scan->results[IE1 + i].probe_sent.icmp, config->source_ip, &packet->length);
        if (packet->data == NULL) {
            fprintf(stderr, "Failed to construct ICMP probe %zu\n", i + 1);
            return -1;
        }
        printf("Constructed ICMP packet number %zu of length: %zu bytes\n", i + 1, packet->length);
    }
    return 0;
}

/**
 * Store the probe specification and construct the packet for the ECN TCP probe.
 * @return 0 on success, -1 on failure.
 */
static int prepare_ecn_probe(struct scan_state *scan, const struct scan_config *config) {
    // Probe Construction
    uint16_t source_port = config->first_source_port + SEQ_PROBE_COUNT;
    struct tcp_probe spec = tcp_ecn_probe_spec(source_port, config->open_port, config->target_ip);

    // Packet Construction
    if (prepare_tcp_probe(scan, config, ECN, spec) < 0)
        return -1;

    printf("Constructed ECN TCP packet of length: %zu bytes\n",
           scan->packets[ECN].length);
    return 0;
}

/**
 * Store the probes specification and construct the packets for the T2-T7 TCP probes.
 * @return 0 on success, -1 on failure.
 */
static int prepare_t_probes(struct scan_state *scan, const struct scan_config *config) {
    uint16_t source_port = config->first_source_port + SEQ_PROBE_COUNT + 1;

    // Probe Construction
    struct tcp_probe *specs = tcp_t_probes_spec(source_port, config->open_port, config->closed_port, config->target_ip);
    if (specs == NULL) {
        fprintf(stderr, "Failed to create T2-T7 probe specifications\n");
        return -1;
    }

    // Packet Construction
    for (size_t i = 0; i < TX_COUNT; i++) {
        if (prepare_tcp_probe(scan, config, T2 + i, specs[i]) < 0) {
            free(specs);
            return -1;
        }
        printf("Constructed T%zu TCP packet of length: %zu bytes\n", i + 2, scan->packets[T2 + i].length);
    }
    free(specs); // Free the specs array after copying the probes into scan->results
    return 0;
}

/**
 * Store the probe specification and construct the packet for the U1 UDP probe.
 * @return 0 on success, -1 on failure.
 */
static int prepare_u1_probe(struct scan_state *scan, const struct scan_config *config) {
    uint16_t source_port = config->first_source_port + SEQ_PROBE_COUNT + TX_COUNT + 1;

    // Probe Construction
    struct udp_probe spec = udp_probe_spec(
        source_port, config->closed_port, config->target_ip);
    struct probe_packet *packet = &scan->packets[U1];
    uint16_t checksum = 0;

    // Packet Construction
    packet->data = construct_UDP_packet(spec, config->source_ip, &packet->length, &checksum);
    if (packet->data == NULL) {
        fprintf(stderr, "Failed to construct UDP packet\n");
        return -1;
    }

    spec.udp_checksum = checksum;
    scan->results[U1].probe_id = U1;
    scan->results[U1].status = PROBE_NOT_SENT;
    scan->results[U1].probe_type = UDP_PROBE;
    scan->results[U1].probe_sent.udp = spec;

    printf("Constructed UDP packet of length: %zu bytes\n\n", packet->length);
    return 0;
}

/**
 * Called the functions to prepare all probes and construct their packets.
 * @return 0 on success, -1 on failure.
 */
int prepare_probes(struct scan_state *scan, const struct scan_config *config) {
    if (scan == NULL || config == NULL)
        return -1;

    if (prepare_sequence_probes(scan, config) < 0 ||
        prepare_ie_probes(scan, config) < 0 ||
        prepare_ecn_probe(scan, config) < 0 ||
        prepare_t_probes(scan, config) < 0 ||
        prepare_u1_probe(scan, config) < 0)
        return -1;

    return 0;
}

/**
 * Initialize the network for the scan.
 * @return 0 on success, -1 on failure.
 */
int open_scan_network(struct network *net, const struct scan_config *config) {
    uint16_t last_tcp_source_port = config->first_source_port + SEQ_PROBE_COUNT + TX_COUNT;

    return network_init(net, config->interface_name, config->source_ip, config->target_ip, config->first_source_port, last_tcp_source_port);
}

/**
 * Send a single probe packet and record the send time.
 * @return 0 on success, -1 on failure.
 */
static int send_one_probe(struct network *net, struct scan_state *scan, size_t index, const struct scan_config *config) {
    struct probe_result *result = &scan->results[index];
    struct probe_packet *packet = &scan->packets[index];

    if (clock_gettime(CLOCK_MONOTONIC, &result->sent_at) != 0) {
        perror("clock_gettime");
        return -1;
    }
    if (send_packet(net, packet->data, packet->length, config->target_ip) != 0) {
        fprintf(stderr, "Failed to send probe at index %zu\n", index);
        return -1;
    }
    result->status = PROBE_NO_RESPONSE;
    return 0;
}

/**
 * Send all the prepared probes.
 * @return 0 on success, -1 on failure.
 */
int send_probes(struct network *net, struct scan_state *scan, const struct scan_config *config) {
    // Send Sequence TCP Probes
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        printf("Sending sequence TCP packet %zu to: %s\n", i + 1, config->target_ip);
        if (send_one_probe(net, scan, i, config) < 0)
            return -1;
        if (i + 1 < SEQ_PROBE_COUNT)
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100000000}, NULL);
    }

    // Send ICMP Echo Probes
    printf("Sending 2 ICMP Echo packets to: %s\n", config->target_ip);
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++) {
        if (send_one_probe(net, scan, IE1 + i, config) < 0)
            return -1;
    }

    // Send ECN TCP Probe
    printf("Sending ECN TCP packet to: %s\n", config->target_ip);
    if (send_one_probe(net, scan, ECN, config) < 0)
        return -1;

    // Send T2-T7 TCP Probes
    for (size_t i = 0; i < TX_COUNT; i++) {
        printf("Sending T%zu TCP packet to: %s\n", i + 2, config->target_ip);
        if (send_one_probe(net, scan, T2 + i, config) < 0)
            return -1;
    }
    
    // Send U1 UDP Probe
    printf("Sending UDP packet to: %s\n", config->target_ip);
    if (send_one_probe(net, scan, U1, config) < 0)
        return -1;

    printf("\nAll probes sent. Waiting for responses...\n\n");
    return 0;
}

/**
 * Collect the responses to the sent probes.
 * @return The number of matched responses, or -1 on failure.
 */
int collect_responses(struct network *net, struct scan_state *scan, const struct scan_config *config) {
    struct in_addr source_address;
    if (inet_pton(AF_INET, config->source_ip, &source_address) != 1) {
        fprintf(stderr, "Invalid source IP\n");
        return -1;
    }

    size_t pending_count = 0;
    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        if (scan->results[i].status == PROBE_NO_RESPONSE)
            pending_count++;
    }

    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        perror("clock_gettime");
        return -1;
    }

    size_t matched_count = 0;
    while (matched_count < pending_count) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            perror("clock_gettime");
            return -1;
        }

        double elapsed = ((double)now.tv_sec - (double)started.tv_sec) +
                         ((double)now.tv_nsec - (double)started.tv_nsec) / 1e9;
        if (elapsed >= config->receive_timeout)
            break;

        struct parsed_info response = {0};
        int status = receive_packet(net, &response);
        if (status == 0) {
            free_parsed_info(&response);
            nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000000}, NULL);
            continue;
        }
        if (status < 0) {
            free_parsed_info(&response);
            fprintf(stderr, "Receiving stopped with status %d\n", status);
            return -1;
        }

        int matched = match_probe_responses(
            scan->results, &response, NUM_PROBES_SENT, 1, source_address);

        /* The existing matcher transfers ownership and clears a matched
           response. Unmatched responses are released here. */
        free_parsed_info(&response);
        if (matched < 0) {
            fprintf(stderr, "Response matching failed\n");
            return -1;
        }
        matched_count += (size_t)matched;
    }

    printf("Matched %zu of %zu pending probes\n", matched_count, pending_count);
    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        if (scan->results[i].status == PROBE_NO_RESPONSE)
            printf("No response for probe at index %zu\n", i);
    }
    printf("\n");
    return (int)matched_count;
}

/**
 * Free the memory allocated for a scan.
 * @param scan The scan to free.
 */
void free_scan(struct scan_state *scan) {
    if (scan == NULL)
        return;

    for (size_t i = 0; i < NUM_PROBES_SENT; i++) {
        free(scan->packets[i].data);
        free_parsed_info(&scan->results[i].parsed_response);
    }

    /* These are the only specifications with heap-allocated payloads. */
    for (size_t i = 0; i < NUM_ICMP_PROBES; i++)
        free(scan->results[IE1 + i].probe_sent.icmp.payload);

    *scan = (struct scan_state){0};
}
