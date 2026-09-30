#include "packet.h"
#include "probes.h"
#include "network.h"
#include "matcher.h"
#include "fingerprint.h"
#include "structures.h"
#include "scan.h"
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
        .open_port = atoi(open_port),
        .closed_port = atoi(closed_port),
        .first_source_port = SRC_PORT_INIT,
        .receive_timeout = 2.5 // Timeout in seconds for receiving responses
    };

    if (config.open_port == 0 || config.closed_port == 0) {
        fprintf(stderr, "Error: Invalid target ports format. Please provide ports in the format <open_port>,<closed_port>\n");
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
