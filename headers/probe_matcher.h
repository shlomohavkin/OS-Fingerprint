#ifndef PROBE_MATCHER_H
#define PROBE_MATCHER_H

#include "packet.h"
#include "probes.h"
#include "structures.h"

/**
 * Matches the received responses to the sent probes based on their specifications.
 * Updates the probe_result structures with the parsed responses and their statuses.
 * @param probe_res Array of probe_result structures representing the sent probes.
 * @param parsed_res Array of parsed_info structures representing the received responses.
 * @param probe_count Number of sent probes in the probe_res array.
 * @param response_count Number of received responses in the parsed_res array.
 * @param source_ip The source IP address used for sending the probes used to match against the responses.
 * @return The number of matched responses, or -1 on failure.
 */
int match_probe_responses(struct probe_result *probe_res, struct parsed_info *parsed_res, size_t probe_count, size_t response_count, struct in_addr source_ip);


#endif // PROBE_MATCHER_H