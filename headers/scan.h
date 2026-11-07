#ifndef SCAN_H
#define SCAN_H

#include "network.h"
#include "structures.h"
#include <stddef.h>
#include <stdint.h>

struct scan_config {
    char *target_ip;
    char *source_ip;
    char *interface_name;
    char *database_path;
    uint16_t open_port;
    uint16_t closed_port;
    uint16_t first_source_port;
    double receive_timeout;
};

struct probe_packet {
    uint8_t *data;
    size_t length;
};

struct scan_state {
    struct probe_result results[NUM_PROBES_SENT];
    struct probe_packet packets[NUM_PROBES_SENT];
};


/**
 * Calls the functions: prepare_sequence_probes, prepare_ie_probes, 
 * prepare_ecn_probe, prepare_t_probes, and prepare_u1_probe
 * to prepare all probes and construct their packets.
 * @param scan Pointer to the scan_state structure to store the prepared probes and packets.
 * @param config Pointer to the scan_config structure containing the necessary parameters.
 * @return 0 on success, -1 on failure.
 */
int prepare_probes(struct scan_state *scan, const struct scan_config *config);

/**
 * Initialize the network for the scan. 
 * @param net Pointer to the network structure to be initialized.
 * @param config Pointer to the scan configuration structure containing the necessary parameters.
 * @return 0 on success, -1 on failure.
 */
int open_scan_network(struct network *net, const struct scan_config *config);

/**
 * Send all the prepared probes.
 * @param net Pointer to the network structure used for sending packets.
 * @param scan Pointer to the scan_state structure containing the prepared probes and packets.
 * @param config Pointer to the scan configuration structure containing the necessary parameters.
 * @return 0 on success, -1 on failure.
 */
int send_probes(struct network *net, struct scan_state *scan, const struct scan_config *config);


/**
 * Collect the responses to the sent probes.
 * @param net Pointer to the network structure used for receiving packets.
 * @param scan Pointer to the scan_state structure containing the sent probes and their results.
 * @param config Pointer to the scan configuration structure containing the necessary parameters.
 * @return The number of matched responses, or -1 on failure.
 */
int collect_responses(struct network *net, struct scan_state *scan, const struct scan_config *config);

/**
 * Free the memory allocated for the scan.
 * @param scan The scan state to free.
 */
void free_scan(struct scan_state *scan);

#endif
