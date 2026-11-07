#include "fingerprint.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define CALCULATED     1   // the test was calculated
#define NOT_AVAILABLE  0   // no reply, or not enough data to calculate the test
#define INVALID       -1

// Fills a probe with a received TCP reply.
static void set_tcp_reply(struct probe_result *probe, uint8_t flags, uint32_t seq, uint16_t ip_id) {
    probe->status = PROBE_RECEIVED;
    probe->probe_type = TCP_PROBE;
    probe->parsed_response.ip_protocol = IPPROTO_TCP;
    probe->parsed_response.ip_id = ip_id;
    probe->parsed_response.app_protocol.tcp_ap.flags = flags;
    probe->parsed_response.app_protocol.tcp_ap.seq = seq;
}

// Six SYN/ACK replies sent 100ms apart: sequence numbers grow by 1000 and IP IDs by 1.
static void make_seq_probes(struct probe_result probes[SEQ_PROBE_COUNT]) {
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        probes[i] = (struct probe_result){0};
        set_tcp_reply(&probes[i], TH_SYN | TH_ACK, (uint32_t)(1000 * i), (uint16_t)(100 + i));
        probes[i].sent_at.tv_nsec = (long)i * 100000000L;
    }
}

static void test_math_helpers(void) {
    uint32_t numbers[] = {12, 18, 24};
    uint32_t prime[] = {3, 5, 7};
    double values[] = {1.0, 2.0, 3.0};

    assert(gcd(12, 18) == 6);
    assert(gcd(0, 5) == 5);
    assert(gcd_array(numbers, 3) == 6);
    assert(gcd_array(prime, 3) == 1);
    assert(gcd_array(NULL, 3) == UNAVAILABLE_SIG);
    assert(standard_deviation(values, 3) == 1.0);
    assert(isnan(standard_deviation(values, 1)));  // needs at least 2 values
}

static void test_seq_fingerprint(void) {
    struct probe_result probes[SEQ_PROBE_COUNT];
    struct seq_fingerprint seq;

    // the replies are 100ms apart, so a step of 1000 is 10000 per second
    uint32_t seqs[3][SEQ_PROBE_COUNT] = {
        {0, 1000, 2000, 3000, 4000, 5000},      // constant step
        {7, 7, 7, 7, 7, 7},                     // constant sequence number
        {0, 1000, 3000, 6000, 10000, 15000},    // growing steps
    };
    uint32_t gcds[] = {1000, 0, 1000};
    uint32_t isrs[] = {106, 0, 119};
    uint32_t sps[] = {0, 0, 32};

    for (size_t i = 0; i < 3; i++) {
        make_seq_probes(probes);
        for (size_t j = 0; j < SEQ_PROBE_COUNT; j++) {
            probes[j].parsed_response.app_protocol.tcp_ap.seq = seqs[i][j];
        }
        assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
        assert(seq.gcd == gcds[i]);
        assert(seq.isr == isrs[i]);
        assert(seq.sp == sps[i]);
        assert(seq.metrics_present);
    }

    // only 3 replies, not enough
    make_seq_probes(probes);
    for (size_t i = 3; i < SEQ_PROBE_COUNT; i++) {
        probes[i].status = PROBE_NO_RESPONSE;
    }
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.gcd == UNAVAILABLE_SIG && !seq.metrics_present);

    // timestamp: no option, zero timestamp, and a rate of 100 per second
    make_seq_probes(probes);
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.ts.kind == TIMESTAMP_UNSUPPORTED);

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        probes[i].parsed_response.app_protocol.tcp_ap.timestamp_present = true;
    }
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.ts.kind == TIMESTAMP_ZERO);

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        probes[i].parsed_response.app_protocol.tcp_ap.tsval = 1000 + 10 * (uint32_t)i;
    }
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.ts.kind == TIMESTAMP_RATE && seq.ts.encoded_rate == 7);

    assert(calculate_seq_fingerprint(NULL, &seq) == INVALID);
    assert(calculate_seq_fingerprint(probes, NULL) == INVALID);
}

static void test_ip_id_and_shared_sequence(void) {
    struct probe_result probes[SEQ_PROBE_COUNT];
    struct ip_id_fingerprint id;

    // TI: every kind of IP ID pattern
    uint16_t ids[7][SEQ_PROBE_COUNT] = {
        {0, 0, 0, 0, 0, 0},                 // zero
        {5, 5, 5, 5, 5, 5},                 // constant
        {100, 101, 102, 103, 104, 105},     // incremental
        {0, 256, 512, 768, 1024, 1280},     // broken incremental
        {0, 1600, 3200, 4800, 6400, 8000},  // random positive
        {0, 30000, 100, 40000, 5, 50000},   // random
        {0, 15, 30, 45, 60, 75},            // no pattern
    };
    enum ip_id_kind kinds[] = {IP_ID_ZERO, IP_ID_CONSTANT, IP_ID_INCREMENTAL, IP_ID_BROKEN_INCREMENTAL,
                               IP_ID_RANDOM_POSITIVE, IP_ID_RANDOM, IP_ID_UNAVAILABLE};

    make_seq_probes(probes);
    for (size_t i = 0; i < 7; i++) {
        for (size_t j = 0; j < SEQ_PROBE_COUNT; j++) {
            probes[j].parsed_response.ip_id = ids[i][j];
        }
        int expected = kinds[i] == IP_ID_UNAVAILABLE ? NOT_AVAILABLE : CALCULATED;
        assert(calculate_ip_id_fingerprints(probes, SEQ_PROBE_COUNT, IP_ID_TEST_TI, &id) == expected);
        assert(id.kind == kinds[i]);
    }
    assert(calculate_ip_id_fingerprints(probes, 7, IP_ID_TEST_TI, &id) == INVALID);  // too many probes

    // CI uses the 3 replies to the closed port
    struct probe_result t_probes[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        set_tcp_reply(&t_probes[i], TH_RST | TH_ACK, 0, (uint16_t)(10 + i));
    }
    assert(calculate_ip_id_fingerprints(t_probes, 3, IP_ID_TEST_CI, &id) == CALCULATED);
    assert(id.kind == IP_ID_INCREMENTAL);

    // SS: the echo reply continues the IP ID counter of the sequence probes (S) or not (O)
    make_seq_probes(probes);  // IP IDs 100..105
    struct probe_result ie[2] = {0};
    struct seq_fingerprint seq = {.ti.kind = IP_ID_INCREMENTAL, .ii.kind = IP_ID_INCREMENTAL};
    ie[0].status = PROBE_RECEIVED;
    ie[1].status = PROBE_RECEIVED;

    ie[0].parsed_response.ip_id = 106;
    assert(calculate_shared_sequence(probes, ie, &seq) == CALCULATED);
    assert(seq.ss == SHARED_SEQUENCE_SAME);

    ie[0].parsed_response.ip_id = 500;
    assert(calculate_shared_sequence(probes, ie, &seq) == CALCULATED);
    assert(seq.ss == SHARED_SEQUENCE_OTHER);

    seq.ti.kind = IP_ID_ZERO;  // TI must be incremental
    assert(calculate_shared_sequence(probes, ie, &seq) == NOT_AVAILABLE);
    assert(calculate_shared_sequence(NULL, ie, &seq) == INVALID);
}

static void test_t_and_ecn_tests(void) {
    calculate_os_fingerprint(NULL);  // resets the hop count, so the TTL guess (TG) is used

    struct tcp_fingerprint tcp;
    struct probe_result probe = {0};
    struct tcp_u *reply = &probe.parsed_response.app_protocol.tcp_ap;
    uint8_t mss[] = {TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4};
    uint8_t bad_options[] = {TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05};  // MSS must be 4 bytes
    uint8_t payload[] = {'a', 'b', 'c'};

    probe.status = PROBE_RECEIVED;
    probe.probe_sent.tcp.seq_num = 100;
    probe.probe_sent.tcp.ack_num = 200;
    probe.parsed_response.ip_ttl = 60;
    probe.parsed_response.ip_fragoff = IP_DF;
    reply->flags = TH_RST | TH_ACK;
    reply->win_size = 0x1000;
    reply->options = mss;
    reply->options_len = sizeof(mss);

    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(tcp.common.R_test && tcp.common.DF_test);
    assert(tcp.common.W_test == 0x1000);
    assert(strcmp(tcp.common.O_test, "M5B4") == 0);
    assert(tcp.common.TG_test == 64);
    assert(strcmp(tcp.common.Q_test, "") == 0);
    assert(strcmp(tcp.S_test, "Z") == 0 && strcmp(tcp.A_test, "Z") == 0);
    assert(strcmp(tcp.F_test, "AR") == 0);

    // S is compared with the sent ack (200), A with the sent seq (100)
    uint32_t seqs[] = {200, 201, 5};
    uint32_t acks[] = {100, 101, 5};
    const char *s_tests[] = {"A", "A+", "O"};
    const char *a_tests[] = {"S", "S+", "O"};
    for (size_t i = 0; i < 3; i++) {
        reply->seq = seqs[i];
        reply->ack = acks[i];
        assert(calculate_t_tests(probe, &tcp) == CALCULATED);
        assert(strcmp(tcp.S_test, s_tests[i]) == 0);
        assert(strcmp(tcp.A_test, a_tests[i]) == 0);
    }

    // Q: reserved bit (R), urgent pointer without the URG flag (U), both (RU)
    uint8_t reserved[] = {1, 0, 1};
    uint16_t urgent[] = {0, 5, 5};
    const char *quirks[] = {"R", "U", "RU"};
    for (size_t i = 0; i < 3; i++) {
        reply->reserved = reserved[i];
        reply->urg_pointer = urgent[i];
        assert(calculate_t_tests(probe, &tcp) == CALCULATED);
        assert(strcmp(tcp.common.Q_test, quirks[i]) == 0);
    }

    // all the flags, and RD (CRC32 of the payload)
    reply->flags = 0x40 | TH_URG | TH_ACK | TH_PUSH | TH_RST | TH_SYN | TH_FIN;
    reply->payload = payload;
    reply->payload_len = sizeof(payload);
    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(strcmp(tcp.F_test, "EUAPRSF") == 0);
    assert(tcp.RD_test == 0x352441C2);  // CRC32 of "abc"

    // invalid options, NULL output, no reply
    struct probe_result lost = {0};
    reply->options = bad_options;
    reply->options_len = sizeof(bad_options);
    assert(calculate_t_tests(probe, &tcp) == INVALID);
    assert(calculate_t_tests(probe, NULL) == INVALID);
    assert(calculate_t_tests(lost, &tcp) == NOT_AVAILABLE);

    // ECN: CC is Y (ECE only), N (neither), S (ECE and CWR) or O (CWR only)
    struct ecn_fingerprint ecn;
    uint8_t ecn_flags[] = {TH_SYN | 0x40, TH_SYN, TH_SYN | 0x40 | 0x80, TH_SYN | 0x80};
    const char *cc[] = {"Y", "N", "S", "O"};
    reply->options = mss;
    reply->options_len = sizeof(mss);
    for (size_t i = 0; i < 4; i++) {
        reply->flags = ecn_flags[i];
        assert(calculate_ecn_fingerprint(probe, &ecn) == CALCULATED);
        assert(strcmp(ecn.CC_test, cc[i]) == 0);
    }
    assert(calculate_ecn_fingerprint(lost, &ecn) == NOT_AVAILABLE);
}

static void test_ie_and_u1(void) {
    calculate_os_fingerprint(NULL);  // resets the hop count, so the TTL guess (TG) is used

    // IE: DFI and CD of the two echo replies
    struct ie_fingerprint ie_fp;
    struct probe_result ie[2] = {0};
    ie[0].status = PROBE_RECEIVED;
    ie[1].status = PROBE_RECEIVED;
    ie[0].parsed_response.ip_ttl = 64;

    assert(calculate_ie_fingerprint(ie, &ie_fp) == CALCULATED);
    assert(strcmp(ie_fp.DFI_test, "N") == 0 && strcmp(ie_fp.CD_test, "Z") == 0);
    assert(ie_fp.TG_test == 64);

    ie[0].parsed_response.ip_fragoff = IP_DF;
    ie[0].parsed_response.app_protocol.icmp_ap.code = 9;
    assert(calculate_ie_fingerprint(ie, &ie_fp) == CALCULATED);
    assert(strcmp(ie_fp.DFI_test, "S") == 0 && strcmp(ie_fp.CD_test, "S") == 0);

    ie[1].status = PROBE_NO_RESPONSE;
    assert(calculate_ie_fingerprint(ie, &ie_fp) == NOT_AVAILABLE);

    // U1: ICMP port unreachable with the quoted UDP probe (20 byte IP header, 8 byte UDP header, 1 data byte)
    struct u1_fingerprint u1_fp;
    struct probe_result u1 = {0};
    uint8_t quoted[29] = {0x45};

    u1.status = PROBE_RECEIVED;
    u1.probe_sent.udp.ip_id = 0x1042;
    u1.probe_sent.udp.ip_ttl = 64;
    u1.probe_sent.udp.udp_checksum = 0xABCD;

    quoted[2] = 0x01;     // IP total length 0x0148
    quoted[3] = 0x48;
    quoted[4] = 0x10;     // IP ID 0x1042
    quoted[5] = 0x42;
    quoted[8] = 60;       // TTL when the probe reached the target
    quoted[9] = IPPROTO_UDP;
    quoted[26] = 0xAB;    // UDP checksum 0xABCD
    quoted[27] = 0xCD;
    quoted[28] = 0x43;    // UDP data 'C'

    u1.parsed_response.ip_protocol = IPPROTO_ICMP;
    u1.parsed_response.ip_ttl = 56;
    u1.parsed_response.ip_fragoff = IP_DF;
    u1.parsed_response.app_protocol.icmp_ap.type = ICMP_DEST_UNREACH;
    u1.parsed_response.app_protocol.icmp_ap.code = ICMP_PORT_UNREACH;
    u1.parsed_response.app_protocol.icmp_ap.payload = quoted;
    u1.parsed_response.app_protocol.icmp_ap.payload_len = sizeof(quoted);

    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(u1_fp.R_test && u1_fp.DF_test);
    assert(u1_fp.T_present && u1_fp.T_test == 60);  // 56 + 4 hops
    assert(u1_fp.RIPL_test.is_good && u1_fp.RID_test.is_good && u1_fp.RUCK_test.is_good);
    assert(u1_fp.RIPCK_test == 'Z');  // zero checksum
    assert(u1_fp.RUD_test);

    // RIPCK with a correct checksum (G), then a wrong one (I)
    uint16_t checksum = calculate_checksum(quoted, 20);
    quoted[10] = (uint8_t)(checksum >> 8);
    quoted[11] = (uint8_t)(checksum & 0xFF);
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(u1_fp.RIPCK_test == 'G');
    quoted[11] ^= 0xFF;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(u1_fp.RIPCK_test == 'I');

    // everything changed: RID, RUCK and RUD
    quoted[5] = 0x00;
    quoted[27] = 0x00;
    quoted[28] = 0x00;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(!u1_fp.RID_test.is_good && !u1_fp.RUCK_test.is_good && !u1_fp.RUD_test);

    // quoted data too short, and no reply
    struct probe_result lost = {0};
    u1.parsed_response.app_protocol.icmp_ap.payload_len = 10;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == INVALID);
    assert(calculate_u1_fingerprint(lost, &u1_fp) == NOT_AVAILABLE);
}

static void test_fingerprint_string(void) {
    // no replies at all
    struct probe_result lost[NUM_PROBES_SENT] = {0};
    char buffer[1024];
    const char *expected = "ECN(R=N)\n"
                           "T1(R=N)\n"
                           "T2(R=N)\n"
                           "T3(R=N)\n"
                           "T4(R=N)\n"
                           "T5(R=N)\n"
                           "T6(R=N)\n"
                           "T7(R=N)\n"
                           "U1(R=N)\n"
                           "IE(R=N)\n";

    assert(generate_fingerprint_string(lost, buffer, sizeof(buffer)) == (int)strlen(expected));
    assert(strcmp(buffer, expected) == 0);

    assert(generate_fingerprint_string(NULL, buffer, sizeof(buffer)) == INVALID);
    assert(generate_fingerprint_string(lost, buffer, 10) == INVALID);  // buffer too small
}

int main(void) {
    test_math_helpers();
    test_seq_fingerprint();
    test_ip_id_and_shared_sequence();
    test_t_and_ecn_tests();
    test_ie_and_u1();
    test_fingerprint_string();

    printf("All fingerprint tests passed successfully.\n");
    return 0;
}