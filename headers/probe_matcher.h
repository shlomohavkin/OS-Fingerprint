#ifndef PROBE_MATCHER_H
#define PROBE_MATCHER_H

#include "packet.h"
#include "probes.h"
#include "structures.h"

int match_probe_responses(struct probe_result *probe_res, struct parsed_info *parsed_res, size_t probe_count, size_t response_count, struct in_addr source_ip);


#endif // PROBE_MATCHER_H