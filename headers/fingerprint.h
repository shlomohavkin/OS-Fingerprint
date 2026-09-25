#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include "packet.h"
#include "structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <netinet/ip.h>
#include <zlib.h> // For CRC32 calculation


#define SEQ_PROBE_COUNT 6
#define OPS_STRING_MAX_LENGTH 128
#define OPTIONS_MAX_LENGTH 40
#define UNAVAILABLE_SIG UINT32_MAX


enum ip_id_kind {
    IP_ID_UNAVAILABLE = 0,
    IP_ID_ZERO,                  // Z
    IP_ID_INCREMENTAL,           // I
    IP_ID_BROKEN_INCREMENTAL,    // BI
    IP_ID_RANDOM_POSITIVE,       // RI
    IP_ID_RANDOM,                // RD
    IP_ID_CONSTANT            
};

struct ip_id_fingerprint {
    enum ip_id_kind kind;
    uint16_t constant_value;     // used for IP_ID_CONSTANT
};

enum shared_sequence {
    SHARED_SEQUENCE_UNAVAILABLE = 0,
    SHARED_SEQUENCE_SAME,        // S
    SHARED_SEQUENCE_OTHER        // O
};

enum timestamp_kind {
    TIMESTAMP_UNAVAILABLE = 0,   // Insufficient information
    TIMESTAMP_UNSUPPORTED,       // U: timestamp option unsupported
    TIMESTAMP_ZERO,              // 0: observed zero timestamp
    TIMESTAMP_RATE               // Encoded rate, printed as hex
};

struct timestamp_fingerprint {
    enum timestamp_kind kind;
    uint32_t encoded_rate;      // used for TIMESTAMP_RATE
};


struct seq_fingerprint {
    uint32_t gcd;
    uint32_t isr;
    uint32_t sp;

    struct ip_id_fingerprint ti;
    struct ip_id_fingerprint ci;
    struct ip_id_fingerprint ii;

    enum shared_sequence ss;
    struct timestamp_fingerprint ts;

    bool metrics_present; // Indicates if the metrics (ISR, SP and GCD) are present

};

struct tcp_common_fingerprint {
    bool R_test;
    bool DF_test;

    uint8_t TG_test;

    uint16_t W_test;
    char O_test[OPS_STRING_MAX_LENGTH];
    char Q_test[3];
};

struct tcp_fingerprint {
    struct tcp_common_fingerprint common;

    char S_test[3];
    char A_test[3];
    char F_test[8];
    uint32_t RD_test;
};

struct ecn_fingerprint {
    struct tcp_common_fingerprint common;

    char CC_test[2];
};

struct ie_fingerprint {
    bool R_test[2];
    uint8_t TG_test[2];

    char DFI_test[2];


    // Only for the first probe
    // uint8_t T_test; // need U1 test
    char CD_test[3];
};

struct os_fingerprint {
    struct seq_fingerprint seq;       // SEQ test 
    struct ecn_fingerprint ecn;       // ECN
    struct tcp_fingerprint tcp[7];    // T1–T7

    char ops[SEQ_PROBE_COUNT][OPS_STRING_MAX_LENGTH]; // O1–O6
    uint16_t win[SEQ_PROBE_COUNT];       // W1–W6

    // struct u1_fingerprint u1;         // U1
    struct ie_fingerprint ie;         // IE

    bool valid; // Indicates if the fingerprint is valid
    bool ops_present[SEQ_PROBE_COUNT];
    bool win_present[SEQ_PROBE_COUNT];
};


struct os_fingerprint calculate_os_fingerprint(struct probe_result *probes);




#endif /* FINGERPRINT_H */