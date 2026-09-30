#include "probe_matcher.h"

static bool matches_quoted_udp(const struct udp_probe *probe, const uint8_t *ip, size_t len, struct in_addr source_ip, struct in_addr target_ip) {
    if (ip == NULL || len < 20 ||
        (ip[0] >> 4) != 4 || ip[9] != IPPROTO_UDP) {
        return false;
    }

    size_t ihl = (ip[0] & 0x0Fu) * 4u;

    if (ihl < 20 || ihl > len || len - ihl < 8) {
        return false;
    }

    /* Reject noninitial fragments. */
    if ((ip[6] & 0x1Fu) != 0 || ip[7] != 0) {
        return false;
    }

    if (memcmp(ip + 12, &source_ip.s_addr, 4) != 0 ||
        memcmp(ip + 16, &target_ip.s_addr, 4) != 0) {
        return false;
    }

    const uint8_t *udp = ip + ihl;
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];

    return src_port == probe->source_port &&
           dst_port == probe->dest_port;
}

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
    case UDP_PROBE:
        if (response->ip_protocol != IPPROTO_ICMP ||
            response->app_protocol.icmp_ap.type != ICMP_DEST_UNREACH ||
            response->app_protocol.icmp_ap.code != ICMP_PORT_UNREACH) {
            return false;
        }
        target = probe->probe_sent.udp.dest_ip;
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
        return probe->probe_sent.tcp.source_port == response->app_protocol.tcp_ap.dst_port &&
            probe->probe_sent.tcp.dest_port == response->app_protocol.tcp_ap.src_port;
    case ICMP_PROBE:
        return probe->probe_sent.icmp.icmp_identifier == response->app_protocol.icmp_ap.header.echo.id &&
            probe->probe_sent.icmp.icmp_sequence == response->app_protocol.icmp_ap.header.echo.seq;
    case UDP_PROBE:
        return matches_quoted_udp(&probe->probe_sent.udp, response->app_protocol.icmp_ap.payload, response->app_protocol.icmp_ap.payload_len, source_ip, target_ip);
    default:
        return false;
    }
}


int match_probe_responses(struct probe_result *probe_res, struct parsed_info *parsed_res, size_t probe_count, size_t response_count, struct in_addr source_ip) {
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