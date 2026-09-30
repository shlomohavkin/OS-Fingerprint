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



int prepare_probes(struct scan_state *scan, const struct scan_config *config);
int open_scan_network(struct network *net, const struct scan_config *config);
int send_probes(struct network *net, struct scan_state *scan,const struct scan_config *config);


int collect_responses(struct network *net, struct scan_state *scan, const struct scan_config *config);
void free_scan(struct scan_state *scan);

#endif
