#include "fingerprint.h"
#include <assert.h>

static void test_empty_options() {
    uint8_t empty_options[] = {};
    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result = generate_ops_string(empty_options, sizeof(empty_options), ops_string);

    assert(result == ops_string);
    assert(strcmp(ops_string, "") == 0);
}

static void test_nop_only() {
    uint8_t nop_only[] = {TCPOPT_NOP};
    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result = generate_ops_string(nop_only, sizeof(nop_only), ops_string);

    assert(result == ops_string);
    assert(strcmp(ops_string, "N") == 0);
}

static void test_mss() {
    uint8_t mss_option[] = {TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4}; // MSS = 1460
    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result = generate_ops_string(mss_option, sizeof(mss_option), ops_string);

    assert(result == ops_string);
    assert(strcmp(ops_string, "M5B4") == 0);
}

static void test_window_scale() {
    uint8_t window_option[] = {TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x0A}; // Window scale = 10
    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result = generate_ops_string(window_option, sizeof(window_option), ops_string);

    assert(result == ops_string);
    assert(strcmp(ops_string, "WA") == 0);
}

static void test_timestamp() {
    uint8_t timestamp_opt_10[] = {
        TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
        0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
        0x00, 0x00, 0x00, 0x00  // Timestamp TSecr
    };
    uint8_t timestamp_opt_01[] = {
        TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
        0x00, 0x00, 0x00, 0x00,  // Timestamp TSVal
        0xFF, 0xFF, 0xFF, 0xFF // Timestamp TSecr
    };
    uint8_t timestamp_opt_00[] = {
        TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
        0x00, 0x00, 0x00, 0x00,  // Timestamp TSVal
        0x00, 0x00, 0x00, 0x00 // Timestamp TSecr
    };
    uint8_t timestamp_opt_11[] = {
        TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
        0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSVal
        0xFF, 0xFF, 0xFF, 0xFF // Timestamp TSecr
    };


    

    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result1 = generate_ops_string(timestamp_opt_10, sizeof(timestamp_opt_10), ops_string);
    assert(result1 == ops_string);
    assert(strcmp(ops_string, "T10") == 0); // TSval is non-zero (1), TSecr is zero (0)

    char *result2 = generate_ops_string(timestamp_opt_01, sizeof(timestamp_opt_01), ops_string);
    assert(result2 == ops_string);
    assert(strcmp(ops_string, "T01") == 0); // TSval is zero (0), TSecr is non-zero (1)

    char *result3 = generate_ops_string(timestamp_opt_00, sizeof(timestamp_opt_00), ops_string);
    assert(result3 == ops_string);
    assert(strcmp(ops_string, "T00") == 0); // TSval is zero (0), TSecr is zero (0)

    char *result4 = generate_ops_string(timestamp_opt_11, sizeof(timestamp_opt_11), ops_string);
    assert(result4 == ops_string);
    assert(strcmp(ops_string, "T11") == 0); // TSval is non-zero (1), TSecr is non-zero (1)
}

static void test_invalid_options() {
    uint8_t invalid_options[] = {
        TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05 // Invalid length for MAXSEG
    };
    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result = generate_ops_string(invalid_options, sizeof(invalid_options), ops_string);

    assert(result == NULL);
    assert(ops_string[0] == '\0');

    assert(generate_ops_string(NULL, sizeof(invalid_options), ops_string) == NULL);
    assert(ops_string[0] == '\0');
}

static void full_test() {
    uint8_t options[] = {
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x0A, // winow scale = 10 - WA
            TCPOPT_NOP, // NOP - N
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4, // MSS = 1460 - M5B4
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp 
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval - 1
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr - 0
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted - S
        };
    char ops_string[OPS_STRING_MAX_LENGTH] = {0};

    char *result = generate_ops_string(options, sizeof(options), ops_string);

    assert(result == ops_string);
    assert(strcmp(ops_string, "WANM5B4T10S") == 0);
}

int main(void) {
    test_empty_options();
    test_nop_only();
    test_mss();
    test_window_scale();
    test_timestamp();
    test_invalid_options();
    full_test();



    printf("All TCP options tests passed successfully.\n");
    return 0;
}