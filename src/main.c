/**
 * @file main.c
 * @author Shlomo Havkin
 * @brief Main entry point for the OS fingerprinting tool.
 * @details This program performs OS fingerprinting by sending crafted 
 * network probes to a target IP address and analyzing the responses.
 * It constructs TCP, ICMP and UDP packets, sends them to the target, collects the responses, 
 * generates a fingerprint string, and matches it against a database of known fingerprints 
 * to identify the operating system of the target.
 */



#include "packet.h"
#include "probes.h"
#include "network.h"
#include "matcher.h"
#include "fingerprint.h"
#include "structures.h"
#include "scan.h"
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

#define MAX_MATCHES 10
#define MAX_FINGERPRINT_LENGTH 1024

/**
 * Function to parse a port number from a string and to validate 
 * that it is within the valid range (1-65535) to avoid integer overflow issues.
 * @return 0 on success, -1 on failure.
 */
static int parse_port(const char *text, uint16_t *port) {
    char *end = NULL;
    unsigned long value;

    if (text == NULL || *text < '0' || *text > '9') {
        return -1;
    }

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' ||
        value < 1 || value > UINT16_MAX) {
        return -1;
    }

    *port = (uint16_t)value;
    return 0;
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    if (argc != 3) {
        printf("Usage: %s <target_ip> <target_ports>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *open_port = strtok(argv[2], ",");
    char *closed_port = strtok(NULL, ",");
    if (open_port == NULL || closed_port == NULL) {
        fprintf(stderr, "Provide ports in the format <open_port>,<closed_port>\n");
        return EXIT_FAILURE;
    }

    uint16_t open_port_number;
    uint16_t closed_port_number;
    if (parse_port(open_port, &open_port_number) < 0 ||
        parse_port(closed_port, &closed_port_number) < 0) {
        fprintf(stderr, "Error: Port numbers must be between 1 and 65535.\n");
        return EXIT_FAILURE;
    }

    char source_ip[INET_ADDRSTRLEN];
    if (get_source_ip(argv[1], source_ip) < 0) {
        fprintf(stderr, "Failed to determine source IP for target %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    char interface_name[IFNAMSIZ];
    if (get_interface_for_ip(source_ip, interface_name, sizeof(interface_name)) < 0) {
        fprintf(stderr, "Failed to determine network interface for source IP %s\n", source_ip);
        return EXIT_FAILURE;
    }
    
    // Fill the scan configuration with the provided arguments and default values
    // for the current scan.
    struct scan_config config = {
        .target_ip = argv[1],
        .source_ip = source_ip,
        .interface_name = interface_name, // eth0 for WSL and ens33 for Ubuntu VM
        .database_path = "nmap-os-db",
        // nmap databse path: /usr/local/share/nmap/nmap-os-db
        .open_port = open_port_number,
        .closed_port = closed_port_number,
        .first_source_port = SRC_PORT_INIT,
        .receive_timeout = 2.5 // Timeout in seconds for receiving responses
    };

    if (config.open_port == config.closed_port) {
        fprintf(stderr, "Error: Invalid target ports. Please provide valid port numbers in the format <open_port>,<closed_port>\n");
        return EXIT_FAILURE;
    }

    printf("Target IP: %s\n", config.target_ip);
    printf("Open Port: %u\n", (unsigned int)config.open_port);
    printf("Closed port: %u\n\n", (unsigned int)config.closed_port);

    int exit_status = EXIT_FAILURE;
    bool network_ready = false;
    struct network net = {.send_socket_fd = -1, .pcap_handle = NULL};
    struct scan_state scan = {0};
    char *fingerprint = NULL;
    struct os_match best_matches[MAX_MATCHES] = {0};
    size_t match_count = 0;

    // Initialize the network to be ready to send and receive packets.
    if (open_scan_network(&net, &config) != 0)
        goto cleanup;
    network_ready = true;

    // Prepare the probes specifications and construct the packets to be sent.
    if (prepare_probes(&scan, &config) < 0)
        goto cleanup;

    // Send the probes to the target ip.
    if (send_probes(&net, &scan, &config) < 0)
        goto cleanup;

    // Collect the responses to the sent probes and match them to the sent probes.
    if (collect_responses(&net, &scan, &config) < 0)
        goto cleanup;

    
    // Fingerprint Generation
    fingerprint = calloc(MAX_FINGERPRINT_LENGTH, sizeof(char));
    if (fingerprint == NULL) {
        fprintf(stderr, "Failed to allocate memory for fingerprint\n");
        goto cleanup;
    }
    if (generate_fingerprint_string(scan.results, fingerprint, MAX_FINGERPRINT_LENGTH) < 0) {
        fprintf(stderr, "Failed to generate fingerprint string\n");
        goto cleanup;
    }
    printf("Fingerprint string: \n%s\n", fingerprint);

    // Database scan and OS matching
    if (find_os_matches(config.database_path, fingerprint, best_matches, MAX_MATCHES, &match_count) != 0) {
        fprintf(stderr, "Failed to find OS matches in the database\n");
        goto cleanup;
    }

    printf("Found %zu possible OS matches:\n", match_count);
    for (size_t i = 0; i < match_count; i++) {
        printf("Match %zu: OS: %s, Score: %.2f%%\n", i + 1, best_matches[i].os_name, best_matches[i].score * 100.0);
    }
    exit_status = EXIT_SUCCESS;

cleanup:
    free_os_matches(best_matches, match_count);
    free(fingerprint);
    free_scan(&scan);
    if (network_ready) {
        pcap_close(net.pcap_handle);
        close(net.send_socket_fd);
    }
    return exit_status;
}
