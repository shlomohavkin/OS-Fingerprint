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
    uint32_t zeros[] = {0, 0};
    double values[] = {1.0, 2.0, 3.0};
    double same[] = {2.0, 2.0, 2.0};

    assert(gcd(12, 18) == 6);
    assert(gcd(0, 5) == 5); // edge: zero operands
    assert(gcd(7, 0) == 7);
    assert(gcd(0, 0) == 0);

    assert(gcd_array(numbers, 3) == 6);
    assert(gcd_array(prime, 3) == 1); 
    assert(gcd_array(zeros, 2) == 0);
    assert(gcd_array(NULL, 3) == UNAVAILABLE_SIG);   // invalid
    assert(gcd_array(numbers, 0) == UNAVAILABLE_SIG);

    assert(standard_deviation(values, 3) == 1.0);
    assert(standard_deviation(same, 3) == 0.0);      // edge: no variation
    assert(isnan(standard_deviation(values, 1)));    // invalid: needs at least 2 values
    assert(isnan(standard_deviation(NULL, 3)));
}

static void test_seq_fingerprint(void) {
    struct probe_result probes[SEQ_PROBE_COUNT];
    struct seq_fingerprint seq;

    // Replies are 100ms apart, so a step of 1000 in the sequence number is 10000 per second.
    uint32_t seqs[4][SEQ_PROBE_COUNT] = {
        {0xFFFFFC18, 0, 1000, 2000, 3000, 4000},  // constant step that wraps around 2^32
        {7, 7, 7, 7, 7, 7},                       // constant sequence number
        {0, 1000, 3000, 6000, 10000, 15000},      // growing steps, GCD above 9
        {0, 1, 3, 6, 10, 15},                     // growing steps, GCD of 1
    };
    uint32_t gcds[] = {1000, 0, 1000, 1};
    uint32_t isrs[] = {106, 0, 119, 39};
    uint32_t sps[] = {0, 0, 32, 32};

    for (size_t i = 0; i < 4; i++) {
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

    // Fewer than 4 usable replies: only SYN/ACK replies that were received count
    make_seq_probes(probes);
    probes[3].parsed_response.app_protocol.tcp_ap.flags = TH_RST | TH_ACK;
    probes[4].status = PROBE_NO_RESPONSE;
    probes[5].status = PROBE_NOT_SENT;
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.gcd == UNAVAILABLE_SIG && seq.isr == UNAVAILABLE_SIG && seq.sp == UNAVAILABLE_SIG);
    assert(!seq.metrics_present);

    // TS: no timestamp option (U), zero timestamp (0), and the rates (step per 100ms -> encoded rate)
    make_seq_probes(probes);
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.ts.kind == TIMESTAMP_UNSUPPORTED);

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        probes[i].parsed_response.app_protocol.tcp_ap.timestamp_present = true;
    }
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.ts.kind == TIMESTAMP_ZERO);

    uint32_t steps[] = {0, 1, 10, 20, 100};
    uint32_t encoded[] = {1, 3, 7, 8, 10};  // rates 0, 10, 100, 200 and 1000 per second
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < SEQ_PROBE_COUNT; j++) {
            probes[j].parsed_response.app_protocol.tcp_ap.tsval = 1000 + steps[i] * (uint32_t)j;
        }
        assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
        assert(seq.ts.kind == TIMESTAMP_RATE);
        assert(seq.ts.encoded_rate == encoded[i]);
    }

    for (size_t i = 1; i < SEQ_PROBE_COUNT; i++) {
        probes[i].status = PROBE_NO_RESPONSE;
    }
    assert(calculate_seq_fingerprint(probes, &seq) == CALCULATED);
    assert(seq.ts.kind == TIMESTAMP_UNAVAILABLE);  // a rate needs at least 2 replies

    // Invalid arguments
    assert(calculate_seq_fingerprint(NULL, &seq) == INVALID);
    assert(calculate_seq_fingerprint(probes, NULL) == INVALID);
}

static void test_ip_id_and_shared_sequence(void) {
    struct probe_result probes[SEQ_PROBE_COUNT];
    struct ip_id_fingerprint id;

    // TI: every IP ID pattern in the six SYN/ACK replies
    uint16_t ids[8][SEQ_PROBE_COUNT] = {
        {0, 0, 0, 0, 0, 0},                 // all zero
        {5, 5, 5, 5, 5, 5},                 // constant
        {100, 101, 102, 103, 104, 105},     // incremental: steps below 10
        {0, 20, 40, 60, 80, 100},           // incremental: even steps
        {0, 256, 512, 768, 1024, 1280},     // broken incremental: steps are multiples of 256
        {0, 1600, 3200, 4800, 6400, 8000},  // random positive: large steps
        {0, 30000, 100, 40000, 5, 50000},   // random: a step above 20000
        {0, 15, 30, 45, 60, 75},            // no pattern
    };
    enum ip_id_kind kinds[] = {IP_ID_ZERO, IP_ID_CONSTANT, IP_ID_INCREMENTAL, IP_ID_INCREMENTAL,
                               IP_ID_BROKEN_INCREMENTAL, IP_ID_RANDOM_POSITIVE, IP_ID_RANDOM,
                               IP_ID_UNAVAILABLE};

    make_seq_probes(probes);
    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < SEQ_PROBE_COUNT; j++) {
            probes[j].parsed_response.ip_id = ids[i][j];
        }
        int expected = kinds[i] == IP_ID_UNAVAILABLE ? NOT_AVAILABLE : CALCULATED;
        assert(calculate_ip_id_fingerprints(probes, SEQ_PROBE_COUNT, IP_ID_TEST_TI, &id) == expected);
        assert(id.kind == kinds[i]);
        assert(id.kind != IP_ID_CONSTANT || id.constant_value == 5);
    }

    // TI needs at least 3 usable replies
    for (size_t i = 2; i < SEQ_PROBE_COUNT; i++) {
        probes[i].status = PROBE_NO_RESPONSE;
    }
    assert(calculate_ip_id_fingerprints(probes, SEQ_PROBE_COUNT, IP_ID_TEST_TI, &id) == NOT_AVAILABLE);
    assert(id.kind == IP_ID_UNAVAILABLE);

    // CI uses the three TCP replies to the closed port (any flags)
    struct probe_result t_probes[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        set_tcp_reply(&t_probes[i], TH_RST | TH_ACK, 0, (uint16_t)(10 + i));
    }
    assert(calculate_ip_id_fingerprints(t_probes, 3, IP_ID_TEST_CI, &id) == CALCULATED);
    assert(id.kind == IP_ID_INCREMENTAL);

    // II uses the two echo replies. With only 2 samples a big step is random positive, not random
    struct probe_result echo[2] = {0};
    for (size_t i = 0; i < 2; i++) {
        echo[i].status = PROBE_RECEIVED;
        echo[i].probe_type = ICMP_PROBE;
        echo[i].parsed_response.ip_protocol = IPPROTO_ICMP;
        echo[i].parsed_response.app_protocol.icmp_ap.type = ICMP_ECHOREPLY;
    }
    echo[1].parsed_response.ip_id = 30000;
    assert(calculate_ip_id_fingerprints(echo, 2, IP_ID_TEST_II, &id) == CALCULATED);
    assert(id.kind == IP_ID_RANDOM_POSITIVE);

    // Invalid arguments
    assert(calculate_ip_id_fingerprints(probes, SEQ_PROBE_COUNT, IP_ID_TEST_TI, NULL) == INVALID);
    assert(calculate_ip_id_fingerprints(NULL, SEQ_PROBE_COUNT, IP_ID_TEST_TI, &id) == INVALID);
    assert(calculate_ip_id_fingerprints(probes, 7, IP_ID_TEST_TI, &id) == INVALID);  // too many probes

    // SS: the echo reply continues the sequence probes' IP ID counter (S) or it does not (O)
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

    // SS unavailable: TI is not incremental / an echo reply is missing / fewer than 3 sequence replies
    seq.ti.kind = IP_ID_ZERO;
    assert(calculate_shared_sequence(probes, ie, &seq) == NOT_AVAILABLE);
    assert(seq.ss == SHARED_SEQUENCE_UNAVAILABLE);

    seq.ti.kind = IP_ID_INCREMENTAL;
    ie[1].status = PROBE_NO_RESPONSE;
    assert(calculate_shared_sequence(probes, ie, &seq) == NOT_AVAILABLE);

    ie[1].status = PROBE_RECEIVED;
    for (size_t i = 2; i < SEQ_PROBE_COUNT; i++) {
        probes[i].status = PROBE_NO_RESPONSE;
    }
    assert(calculate_shared_sequence(probes, ie, &seq) == NOT_AVAILABLE);

    assert(calculate_shared_sequence(NULL, ie, &seq) == INVALID);
}

static void test_t_and_ecn_tests(void) {
    calculate_os_fingerprint(NULL);  // resets the internal hop count, so the TTL guess (TG) is used

    struct tcp_fingerprint tcp;
    struct probe_result probe = {0};
    struct tcp_u *reply = &probe.parsed_response.app_protocol.tcp_ap;
    uint8_t mss[] = {TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4};
    uint8_t bad_options[] = {TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05};  // MSS option must be 4 bytes
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

    // R, DF, W, O, TG, Q, S, A, F and RD of a received reply
    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(tcp.common.R_test && tcp.common.DF_test);
    assert(tcp.common.W_test == 0x1000);
    assert(strcmp(tcp.common.O_test, "M5B4") == 0);
    assert(tcp.common.TG_test == 64 && !tcp.common.T_present);
    assert(strcmp(tcp.common.Q_test, "") == 0);
    assert(strcmp(tcp.S_test, "Z") == 0 && strcmp(tcp.A_test, "Z") == 0);
    assert(strcmp(tcp.F_test, "AR") == 0);
    assert(tcp.RD_test == 0);

    probe.parsed_response.ip_fragoff = 0;
    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(!tcp.common.DF_test);

    // S (compared with the sent ACK number 200) and A (compared with the sent sequence number 100)
    uint32_t seqs[] = {0, 200, 201, 5};
    uint32_t acks[] = {0, 100, 101, 5};
    const char *s_tests[] = {"Z", "A", "A+", "O"};
    const char *a_tests[] = {"Z", "S", "S+", "O"};
    for (size_t i = 0; i < 4; i++) {
        reply->seq = seqs[i];
        reply->ack = acks[i];
        assert(calculate_t_tests(probe, &tcp) == CALCULATED);
        assert(strcmp(tcp.S_test, s_tests[i]) == 0);
        assert(strcmp(tcp.A_test, a_tests[i]) == 0);
    }

    // TG: the TTL guess rounds up to 32, 64, 128 or 255
    uint8_t ttls[] =    {30, 32, 33, 64, 65, 128, 129, 255};
    uint8_t guesses[] = {32, 32, 64, 64, 128, 128, 255, 255};
    for (size_t i = 0; i < 8; i++) {
        probe.parsed_response.ip_ttl = ttls[i];
        assert(calculate_t_tests(probe, &tcp) == CALCULATED);
        assert(tcp.common.TG_test == guesses[i]);
    }

    // Q: reserved bit (R), urgent pointer set without the URG flag (U), both (RU)
    uint8_t reserved[] = {0, 1, 0, 1};
    uint16_t urgent[] = {0, 0, 5, 5};
    const char *quirks[] = {"", "R", "U", "RU"};
    for (size_t i = 0; i < 4; i++) {
        reply->reserved = reserved[i];
        reply->urg_pointer = urgent[i];
        assert(calculate_t_tests(probe, &tcp) == CALCULATED);
        assert(strcmp(tcp.common.Q_test, quirks[i]) == 0);
    }

    // F with every flag, and RD (CRC32 of the payload, only when RST is set)
    reply->flags = 0x40 | TH_URG | TH_ACK | TH_PUSH | TH_RST | TH_SYN | TH_FIN;
    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(strcmp(tcp.F_test, "EUAPRSF") == 0);

    reply->payload = payload;
    reply->payload_len = sizeof(payload);
    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(tcp.RD_test == 0x352441C2);   // CRC32 of "abc"

    reply->flags = TH_ACK;
    assert(calculate_t_tests(probe, &tcp) == CALCULATED);
    assert(tcp.RD_test == 0);

    // Invalid: RST with a payload length but no payload / invalid TCP options / NULL output
    reply->flags = TH_RST;
    reply->payload = NULL;
    assert(calculate_t_tests(probe, &tcp) == INVALID);
    reply->payload_len = 0;
    reply->options = bad_options;
    reply->options_len = sizeof(bad_options);
    assert(calculate_t_tests(probe, &tcp) == INVALID);
    assert(calculate_t_tests(probe, NULL) == INVALID);

    struct probe_result lost = {0};
    assert(calculate_t_tests(lost, &tcp) == NOT_AVAILABLE);
    assert(!tcp.common.R_test);

    // ECN: CC is Y (ECE only), N (neither), S (ECE and CWR) or O (CWR only)
    struct ecn_fingerprint ecn;
    uint8_t ecn_flags[] = {TH_SYN | TH_ACK | 0x40, TH_SYN | TH_ACK,
                           TH_SYN | TH_ACK | 0x40 | 0x80, 
                           TH_SYN | TH_ACK | 0x80};
    const char *cc[] = {"Y", "N", "S", "O"};
    reply->options = mss;
    reply->options_len = sizeof(mss);
    for (size_t i = 0; i < 4; i++) {
        reply->flags = ecn_flags[i];
        assert(calculate_ecn_fingerprint(probe, &ecn) == CALCULATED);
        assert(strcmp(ecn.CC_test, cc[i]) == 0);
    }
    assert(calculate_ecn_fingerprint(lost, &ecn) == NOT_AVAILABLE);
    assert(calculate_ecn_fingerprint(probe, NULL) == INVALID);
}

static void test_ie_and_u1(void) {
    calculate_os_fingerprint(NULL);  // resets the internal hop count, so the TTL guess (TG) is used

    // IE: DFI and CD for every combination of the two echo replies
    struct ie_fingerprint ie_fp;
    struct probe_result ie[2] = {0};
    int df1[] = {0, 1, 1, 0};
    int df2[] = {0, 1, 0, 1};
    uint8_t code1[] = {0, 9, 3, 1};
    uint8_t code2[] = {0, 0, 3, 2};
    const char *dfi[] = {"N", "Y", "S", "O"};
    const char *cd[] = {"Z", "S", "3", "O"};

    ie[0].status = PROBE_RECEIVED;
    ie[1].status = PROBE_RECEIVED;
    ie[0].parsed_response.ip_ttl = 64;
    for (size_t i = 0; i < 4; i++) {
        ie[0].parsed_response.ip_fragoff = df1[i] ? IP_DF : 0;
        ie[1].parsed_response.ip_fragoff = df2[i] ? IP_DF : 0;
        ie[0].parsed_response.app_protocol.icmp_ap.code = code1[i];
        ie[1].parsed_response.app_protocol.icmp_ap.code = code2[i];
        assert(calculate_ie_fingerprint(ie, &ie_fp) == CALCULATED);
        assert(ie_fp.R_test);
        assert(strcmp(ie_fp.DFI_test, dfi[i]) == 0);
        assert(strcmp(ie_fp.CD_test, cd[i]) == 0);
        assert(ie_fp.TG_test == 64 && !ie_fp.T_present);
    }

    ie[1].status = PROBE_NO_RESPONSE;
    assert(calculate_ie_fingerprint(ie, &ie_fp) == NOT_AVAILABLE);
    assert(!ie_fp.R_test);
    ie[1].status = PROBE_RECEIVED;
    assert(calculate_ie_fingerprint(ie, NULL) == INVALID);

    // U1: ICMP port unreachable that quotes the UDP probe (20 byte IP header, 8 byte UDP header, 1 data byte)
    struct u1_fingerprint u1_fp;
    struct probe_result u1 = {0};
    uint8_t quoted[29] = {0x45};

    u1.status = PROBE_RECEIVED;
    u1.probe_sent.udp.ip_id = 0x1042;
    u1.probe_sent.udp.ip_ttl = 64;
    u1.probe_sent.udp.udp_checksum = 0xABCD;

    quoted[2] = 0x01;      // quoted IP total length: 0x0148 = 328
    quoted[3] = 0x48;
    quoted[4] = 0x10;      // quoted IP ID: 0x1042
    quoted[5] = 0x42;
    quoted[8] = 60;        // TTL of the probe when it reached the target
    quoted[9] = IPPROTO_UDP;
    quoted[26] = 0xAB;     // quoted UDP checksum: 0xABCD
    quoted[27] = 0xCD;
    quoted[28] = 0x43;     // UDP data: 'C'

    u1.parsed_response.ip_protocol = IPPROTO_ICMP;
    u1.parsed_response.ip_ttl = 56;
    u1.parsed_response.ip_tot_length = 56;
    u1.parsed_response.ip_fragoff = IP_DF;
    u1.parsed_response.app_protocol.icmp_ap.type = ICMP_DEST_UNREACH;
    u1.parsed_response.app_protocol.icmp_ap.code = ICMP_PORT_UNREACH;
    u1.parsed_response.app_protocol.icmp_ap.header.unreachable.unused = 7;
    u1.parsed_response.app_protocol.icmp_ap.payload = quoted;
    u1.parsed_response.app_protocol.icmp_ap.payload_len = sizeof(quoted);

    // Everything intact (the quoted IP checksum is zero)
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(u1_fp.R_test && u1_fp.DF_test);
    assert(u1_fp.T_present && u1_fp.T_test == 60);  // reply TTL 56 + 4 hops (64 - 60)
    assert(u1_fp.IPL_test == 56 && u1_fp.UN_test == 7);
    assert(u1_fp.RIPL_test.is_good && u1_fp.RID_test.is_good && u1_fp.RUCK_test.is_good);
    assert(u1_fp.RIPCK_test == 'Z');
    assert(u1_fp.RUD_test);

    // RIPCK: a correct checksum (G), then a corrupted one (I)
    uint16_t checksum = calculate_checksum(quoted, 20);
    quoted[10] = (uint8_t)(checksum >> 8);
    quoted[11] = (uint8_t)(checksum & 0xFF);
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(u1_fp.RIPCK_test == 'G');
    quoted[11] ^= 0xFF;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(u1_fp.RIPCK_test == 'I');

    // Everything changed: DF, RIPL, RID, RUCK and RUD
    u1.parsed_response.ip_fragoff = 0;
    quoted[3] = 0x00;
    quoted[5] = 0x00;
    quoted[27] = 0x00;
    quoted[28] = 0x00;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(!u1_fp.DF_test);
    assert(!u1_fp.RIPL_test.is_good && !u1_fp.RID_test.is_good);
    assert(!u1_fp.RUCK_test.is_good && !u1_fp.RUD_test);

    // The hop count (4) is now known, so T replaces the TTL guess (TG) in the other tests
    struct probe_result tcp_probe = {0};
    struct tcp_fingerprint tcp;
    tcp_probe.status = PROBE_RECEIVED;
    tcp_probe.parsed_response.ip_ttl = 60;
    assert(calculate_t_tests(tcp_probe, &tcp) == CALCULATED);
    assert(tcp.common.T_present && tcp.common.T_test == 64);
    assert(calculate_ie_fingerprint(ie, &ie_fp) == CALCULATED);
    assert(ie_fp.T_present && ie_fp.T_test == 68);

    // A quoted TTL above the sent TTL gives a negative hop count: no T, a TTL guess instead
    quoted[8] = 70;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == CALCULATED);
    assert(!u1_fp.T_present && u1_fp.TG_test == 64);

    // Invalid: quoted data too short / not a port unreachable message / NULL output / no reply
    u1.parsed_response.app_protocol.icmp_ap.payload_len = 10;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == INVALID);
    u1.parsed_response.app_protocol.icmp_ap.payload_len = sizeof(quoted);
    u1.parsed_response.app_protocol.icmp_ap.type = ICMP_ECHOREPLY;
    assert(calculate_u1_fingerprint(u1, &u1_fp) == INVALID);
    assert(calculate_u1_fingerprint(u1, NULL) == INVALID);

    struct probe_result lost = {0};
    assert(calculate_u1_fingerprint(lost, &u1_fp) == NOT_AVAILABLE);
}

static void test_fingerprint_string(void) {
    // No replies at all: every part that can be reported as "not received" is
    struct probe_result lost[NUM_PROBES_SENT] = {0};
    char buffer[1024];
    const char *expected =  "ECN(R=N)\n"
                            "T1(R=N)\n"
                            "T2(R=N)\n"
                            "T3(R=N)\n"
                            "T4(R=N)\n"
                            "T5(R=N)\n"
                            "T6(R=N)\n"
                            "T7(R=N)\n"
                            "U1(R=N)\n"
                            "IE(R=N)\n";

    assert(calculate_os_fingerprint(lost).valid);
    assert(generate_fingerprint_string(lost, buffer, sizeof(buffer)) == (int)strlen(expected));
    assert(strcmp(buffer, expected) == 0);

    // Invalid: NULL probes, NULL buffer, zero capacity, buffer too small
    assert(!calculate_os_fingerprint(NULL).valid);
    assert(generate_fingerprint_string(NULL, buffer, sizeof(buffer)) == INVALID);
    assert(generate_fingerprint_string(lost, NULL, sizeof(buffer)) == INVALID);
    assert(generate_fingerprint_string(lost, buffer, 0) == INVALID);
    assert(generate_fingerprint_string(lost, buffer, 10) == INVALID);
}

int main(void) {
    test_math_helpers();
    test_seq_fingerprint();
    test_ip_id_and_shared_sequence();
    test_t_and_ecn_tests();
    test_ie_and_u1();
    test_fingerprint_string();

    printf("All fingerprint tests passed successfully.\n\n");
    return 0;
}