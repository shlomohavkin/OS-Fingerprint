#include "probe_matcher.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define INVALID   -1
#define NO_MATCH   0
#define ONE_MATCH  1

static void test_invalid_arguments(void) {
    struct in_addr source = {0};
    struct probe_result probe = {0};
    struct parsed_info response = {0};

    assert(match_probe_responses(NULL, &response, 1, 1, source) == INVALID);
    assert(match_probe_responses(&probe, NULL, 1, 1, source) == INVALID);
}

static void test_tcp_match(void) {
    struct in_addr source = {inet_addr("10.0.0.1")};
    struct in_addr target = {inet_addr("10.0.0.2")};
    struct probe_result probe = {
        .status = PROBE_NO_RESPONSE,
        .probe_type = TCP_PROBE,
        .probe_sent.tcp = {.dest_ip = "10.0.0.2", .source_port = 1000, .dest_port = 80},
    };
    struct parsed_info wrong_port = {
        .src_ip = target, .dst_ip = source, .ip_protocol = IPPROTO_TCP,
        .app_protocol.tcp_ap = {.src_port = 81, .dst_port = 1000},
    };
    struct parsed_info response = {
        .src_ip = target, .dst_ip = source, .ip_protocol = IPPROTO_TCP,
        .app_protocol.tcp_ap = {.src_port = 80, .dst_port = 1000, .seq = 42},
    };

    assert(match_probe_responses(&probe, &wrong_port, 1, 1, source) == NO_MATCH);
    assert(probe.status == PROBE_NO_RESPONSE);

    assert(match_probe_responses(&probe, &response, 1, 1, source) == ONE_MATCH);
    assert(probe.status == PROBE_RECEIVED);
    assert(probe.parsed_response.app_protocol.tcp_ap.seq == 42);  // response copied into the probe
    assert(response.ip_protocol == 0);                            // matched response is cleared
}

static void test_icmp_echo_match(void) {
    struct in_addr source = {inet_addr("10.0.0.1")};
    struct in_addr target = {inet_addr("10.0.0.2")};
    struct probe_result probe = {
        .status = PROBE_NO_RESPONSE,
        .probe_type = ICMP_PROBE,
        .probe_sent.icmp = {.dest_ip = "10.0.0.2", .icmp_identifier = 7, .icmp_sequence = 295},
    };
    struct parsed_info wrong_sequence = {
        .src_ip = target, .dst_ip = source, .ip_protocol = IPPROTO_ICMP,
        .app_protocol.icmp_ap = {.type = ICMP_ECHOREPLY, .header.echo = {.id = 7, .seq = 296}},
    };
    struct parsed_info response = {
        .src_ip = target, .dst_ip = source, .ip_protocol = IPPROTO_ICMP,
        .app_protocol.icmp_ap = {.type = ICMP_ECHOREPLY, .header.echo = {.id = 7, .seq = 295}},
    };

    assert(match_probe_responses(&probe, &wrong_sequence, 1, 1, source) == NO_MATCH);
    assert(match_probe_responses(&probe, &response, 1, 1, source) == ONE_MATCH);
    assert(probe.status == PROBE_RECEIVED);
}

static void test_udp_port_unreachable_match(void) {
    struct in_addr source = {inet_addr("10.0.0.1")};
    struct in_addr target = {inet_addr("10.0.0.2")};
    struct probe_result probe = {
        .status = PROBE_NO_RESPONSE,
        .probe_type = UDP_PROBE,
        .probe_sent.udp = {.dest_ip = "10.0.0.2", .source_port = 200, .dest_port = 81},
    };

    // Quoted IP header (20 bytes) + quoted UDP header (8 bytes) inside the ICMP payload
    uint8_t quoted[28] = {0x45};
    quoted[9] = IPPROTO_UDP;
    memcpy(quoted + 12, &source.s_addr, 4);
    memcpy(quoted + 16, &target.s_addr, 4);
    quoted[21] = 200;  // UDP source port
    quoted[23] = 82;   // UDP destination port (wrong, the probe was sent to 81)

    struct parsed_info response = {
        .src_ip = target, .dst_ip = source, .ip_protocol = IPPROTO_ICMP,
        .app_protocol.icmp_ap = {.type = ICMP_DEST_UNREACH, .code = ICMP_PORT_UNREACH,
                                 .payload = quoted, .payload_len = sizeof(quoted)},
    };

    assert(match_probe_responses(&probe, &response, 1, 1, source) == NO_MATCH);

    quoted[23] = 81;
    assert(match_probe_responses(&probe, &response, 1, 1, source) == ONE_MATCH);
    assert(probe.status == PROBE_RECEIVED);
}

static void test_each_response_matches_one_probe(void) {
    struct in_addr source = {inet_addr("10.0.0.1")};
    struct in_addr target = {inet_addr("10.0.0.2")};
    struct probe_result probe = {
        .status = PROBE_NO_RESPONSE,
        .probe_type = TCP_PROBE,
        .probe_sent.tcp = {.dest_ip = "10.0.0.2", .source_port = 1000, .dest_port = 80},
    };
    struct probe_result probes[2] = {probe, probe};  // two identical probes
    struct parsed_info first = {
        .src_ip = target, .dst_ip = source, .ip_protocol = IPPROTO_TCP,
        .app_protocol.tcp_ap = {.src_port = 80, .dst_port = 1000},
    };
    struct parsed_info second = first;

    // One response can only match one probe
    assert(match_probe_responses(probes, &first, 2, 1, source) == ONE_MATCH);
    assert(probes[0].status == PROBE_RECEIVED);
    assert(probes[1].status == PROBE_NO_RESPONSE);

    // A probe that already has a response is skipped
    assert(match_probe_responses(probes, &second, 2, 1, source) == ONE_MATCH);
    assert(probes[1].status == PROBE_RECEIVED);
}

int main(void) {
    test_invalid_arguments();
    test_tcp_match();
    test_icmp_echo_match();
    test_udp_port_unreachable_match();
    test_each_response_matches_one_probe();

    printf("All probe matcher tests passed successfully.\n");
    return 0;
}