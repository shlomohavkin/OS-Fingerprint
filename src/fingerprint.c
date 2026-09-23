#include "fingerprint.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <zlib.h>


#define UNAVAILABLE_SIG UINT32_MAX

struct seq_samples {
    size_t count;
    size_t index[SEQ_PROBE_COUNT];
    uint32_t diffs[SEQ_PROBE_COUNT - 1];
    double rates[SEQ_PROBE_COUNT - 1];
};

/* HELPER FUNCTIONS  */
static uint32_t seq_diff_calc(uint32_t current, uint32_t previous) {
    uint32_t forward = (uint32_t)(current - previous);
    uint32_t backward = (uint32_t)(previous - current);
    return forward < backward ? forward : backward;
}

static double elapsed_seconds(struct timespec previous, struct timespec next) {
    return ((double)next.tv_sec - (double)previous.tv_sec) +
           ((double)next.tv_nsec - (double)previous.tv_nsec) / 1e9;
}

static struct seq_samples find_seq_samples(const struct tcp_probe_res *probes) {
    struct seq_samples samples = {0};
    if (probes == NULL) {
        return samples;
    }

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (probes[i].status != PROBE_RECEIVED) {
            continue;
        }
        uint8_t flags = probes[i].response.app_protocol.tcp_ap.flags;
        if ((flags & (TH_SYN | TH_ACK | TH_RST)) == (TH_SYN | TH_ACK)) {
            samples.index[samples.count++] = i;
        }
    }
    return samples;
}

static bool calculate_rates(const struct tcp_probe_res *probes, struct seq_samples *samples) {
    if (samples->count < 2) {
        return false;
    }
    for (size_t i = 0; i + 1 < samples->count; i++) {
        size_t current = samples->index[i];
        size_t next = samples->index[i + 1];
        double elapsed = elapsed_seconds(probes[current].sent_at, probes[next].sent_at);
        if (elapsed <= 0.0) {
            return false;
        }
        samples->diffs[i] = seq_diff_calc(
            probes[next].response.app_protocol.tcp_ap.seq,
            probes[current].response.app_protocol.tcp_ap.seq);
        samples->rates[i] = (double)samples->diffs[i] / elapsed;
        if (!isfinite(samples->rates[i])) {
            return false;
        }
    }
    return true;
}

uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

uint32_t gcd_array(uint32_t *arr, size_t len) {
    if (arr == NULL || len == 0) {
        return UNAVAILABLE_SIG;
    }
    uint32_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result = gcd(result, arr[i]);
        if (result == 1) {
            break;
        }
    }
    return result;
}

double standard_deviation(const double *arr, size_t len) {
    if (arr == NULL || len < 2) {
        return NAN;
    }
    double mean = 0.0;
    for (size_t i = 0; i < len; i++) {
        mean += arr[i];
    }
    mean /= (double)len;

    double variance = 0.0;
    for (size_t i = 0; i < len; i++) {
        double difference = arr[i] - mean;
        variance += difference * difference;
    }
    return sqrt(variance / (double)(len - 1));
}



/* TEST CALCULATION FUNCTIONS */
uint32_t calculate_gcd_test(struct tcp_probe_res *probes) {
    struct seq_samples samples = find_seq_samples(probes);
    if (samples.count < 4 || !calculate_rates(probes, &samples)) {
        return UNAVAILABLE_SIG;
    }
    return gcd_array(samples.diffs, samples.count - 1);
}

uint32_t calculate_isr_test(struct tcp_probe_res *probes) {
    struct seq_samples samples = find_seq_samples(probes);
    if (samples.count < 4 || !calculate_rates(probes, &samples)) {
        return UNAVAILABLE_SIG;
    }

    double mean = 0.0;
    for (size_t i = 0; i + 1 < samples.count; i++) {
        mean += samples.rates[i];
    }
    double rate = mean / (double)(samples.count - 1);

    if (!isfinite(rate) || rate < 0.0) {
        return UNAVAILABLE_SIG;
    }
    return rate <= 1.0 ? 0 : (uint32_t)round(8.0 * log2(rate));
}

uint32_t calculate_sp_test(struct tcp_probe_res *probes, uint32_t gcd_value) {
    struct seq_samples samples = find_seq_samples(probes);
    if (samples.count < 4 || !calculate_rates(probes, &samples) ||
        gcd_value == UNAVAILABLE_SIG) {
        return UNAVAILABLE_SIG;
    }

    if (gcd_value == 0) {
        return 0; // Constant ISNs produce zero SP
    }
    double values[SEQ_PROBE_COUNT - 1];
    for (size_t i = 0; i + 1 < samples.count; i++) {
        values[i] = gcd_value > 9 ? samples.rates[i] / gcd_value : samples.rates[i];
    }
    double deviation = standard_deviation(values, samples.count - 1);

    if (!isfinite(deviation) || deviation < 0.0) {
        return UNAVAILABLE_SIG;
    }
    return deviation <= 1.0 ? 0 : (uint32_t)round(8.0 * log2(deviation));
}


struct ip_id_fingerprint calculate_ip_id_fingerprints_ti(struct tcp_probe_res *probes) {
    struct ip_id_fingerprint result = {.kind = IP_ID_UNAVAILABLE};
    struct seq_samples samples = find_seq_samples(probes);
    if (samples.count < 3) {
        return result;
    }

    bool is_all_zero = true;
    bool is_identical = true;
    bool is_broken_incremental = true;
    bool is_incremental = true;
    bool is_all_even = true;
    bool is_random_positive = false;

    for (size_t i = 0; i < samples.count; i++) {
        if (probes[samples.index[i]].response.ip_id != 0) {
            is_all_zero = false;
        }
    }
    if (is_all_zero) {
        result.kind = IP_ID_ZERO;
        return result;
    }

    for (size_t i = 0; i + 1 < samples.count; i++) {
        uint16_t curr_id = probes[samples.index[i]].response.ip_id;
        uint16_t next_id = probes[samples.index[i + 1]].response.ip_id;

        // We first calculate the difference in the 32bit reprsentation 
        // of the IP IDs to handle wraparound correctly for the RD flag. 
        // Then we check the rest with the 16bit rep.
        uint32_t raw_diff = (uint32_t)next_id - (uint32_t)curr_id;
        if (raw_diff > 20000u) {
            result.kind = IP_ID_RANDOM;
            return result;
        }

        uint16_t diff = (uint16_t)raw_diff;
        if (diff != 0) {
            is_identical = false;
        }
        if (!(diff % 256 == 0 && diff <= 5120)) {
            is_broken_incremental = false;
        }
        if (diff >= 10) {
            is_incremental = false;
        }
        if (diff % 2 != 0) {
            is_all_even = false;
        }
        if ((diff % 256 != 0 && diff > 1000) ||
            (diff % 256 == 0 && diff >= 25600)) {
            is_random_positive = true;
        }
    }

    if (is_identical) {
        result.kind = IP_ID_CONSTANT;
        result.constant_value = probes[samples.index[0]].response.ip_id;
    } else if (is_random_positive) {
        result.kind = IP_ID_RANDOM_POSITIVE;
    } else if (is_broken_incremental) {
        result.kind = IP_ID_BROKEN_INCREMENTAL;
    } else if (is_all_even || is_incremental) {
        result.kind = IP_ID_INCREMENTAL;
    }
    return result;
}

struct timestamp_fingerprint calculate_timestamp_fingerprint(struct tcp_probe_res *probes) {
    struct timestamp_fingerprint result = {.kind = TIMESTAMP_UNAVAILABLE};
    struct seq_samples samples = find_seq_samples(probes);
    if (samples.count == 0) {
        return result;
    }

    bool missing_option = false;
    bool zero_value = false;
    for (size_t i = 0; i < samples.count; i++) {
        size_t index = samples.index[i];
        if (!probes[index].response.app_protocol.tcp_ap.timestamp_present) {
            missing_option = true;
        } else if (probes[index].response.app_protocol.tcp_ap.tsval == 0) {
            zero_value = true;
        }
    }
    if (missing_option) {
        result.kind = TIMESTAMP_UNSUPPORTED;
        return result;
    }
    if (zero_value) {
        result.kind = TIMESTAMP_ZERO;
        return result;
    }
    if (samples.count < 2) {
        return result;
    }

    double average_ts_inc_sec = 0.0;
    for (size_t i = 0; i + 1 < samples.count; i++) {
        size_t current = samples.index[i];
        size_t next = samples.index[i + 1];
        double elapsed = elapsed_seconds(probes[current].sent_at, probes[next].sent_at);
        if (elapsed <= 0.0) {
            return result;
        }
        uint32_t diff = seq_diff_calc(probes[next].response.app_protocol.tcp_ap.tsval,
                                    probes[current].response.app_protocol.tcp_ap.tsval);
        average_ts_inc_sec += (double)diff / elapsed;
    }
    average_ts_inc_sec /= (double)(samples.count - 1);
    if (!isfinite(average_ts_inc_sec) || average_ts_inc_sec <= 0.0) {
        return result; 
    }

    result.kind = TIMESTAMP_RATE;
    if (average_ts_inc_sec <= 5.66) {
        result.encoded_rate = 1;
    } else if (average_ts_inc_sec > 70.0 && average_ts_inc_sec <= 150.0) {
        result.encoded_rate = 7;
    } else if (average_ts_inc_sec > 150.0 && average_ts_inc_sec <= 350.0) {
        result.encoded_rate = 8;
    } else {
        result.encoded_rate = (uint32_t)round(log2(average_ts_inc_sec));
    }
    return result;
}

int calculate_seq_fingerprint(struct tcp_probe_res *probes, struct seq_fingerprint *fingerprint) {
    if (probes == NULL || fingerprint == NULL) {
        return -1;
    }
    *fingerprint = (struct seq_fingerprint){0};


    fingerprint->gcd = calculate_gcd_test(probes);
    fingerprint->isr = calculate_isr_test(probes);
    fingerprint->sp = calculate_sp_test(probes, fingerprint->gcd);
    fingerprint->ti = calculate_ip_id_fingerprints_ti(probes);
    fingerprint->ts = calculate_timestamp_fingerprint(probes);
    fingerprint->metrics_present = fingerprint->isr != UNAVAILABLE_SIG &&
                                    fingerprint->sp != UNAVAILABLE_SIG;
    /* CI, II and SS remain unavailable until their additional probes exist. */
    return 1;
}


char *generate_ops_string(const uint8_t *options, size_t options_len, char *ops_string) {
    if (ops_string == NULL) {
        return NULL;
    }
    ops_string[0] = '\0'; // Initialize the ops_string to an empty string
    if (options_len == 0) {
        return ops_string; // Return an empty string if there are no options
    }
    if (options == NULL || options_len > OPTIONS_MAX_LENGTH) {
        return NULL;
    }

    size_t ops_index = 0;
    for (size_t i = 0; i < options_len; i++) {
        uint8_t option_type = options[i];

        // CHECKS TO ENSURE VALIDITY OF TCP OPTIONS
        if (option_type != TCPOPT_EOL && option_type != TCPOPT_NOP) {
            if (options_len - i < 2) {
                ops_string[0] = '\0';
                return NULL;
            }
            size_t cur_option_len = options[i + 1];
            if (cur_option_len < 2 || cur_option_len > options_len - i) {
                ops_string[0] = '\0';
                return NULL;
            }
            if ((option_type == TCPOPT_MAXSEG && cur_option_len != 4) ||
                (option_type == TCPOPT_WINDOW && cur_option_len != 3) ||
                (option_type == TCPOPT_SACK_PERMITTED && cur_option_len != 2) ||
                (option_type == TCPOPT_TIMESTAMP && cur_option_len != 10)) {
                ops_string[0] = '\0';
                return NULL;
            }
        }

        size_t needed_space;
        switch (option_type) {
        case TCPOPT_EOL:
        case TCPOPT_NOP:
        case TCPOPT_SACK_PERMITTED:
            needed_space = 1; // Single character
            break;
        case TCPOPT_MAXSEG:
            needed_space = 5; // 'M' + 4 hex digits
            break;
        case TCPOPT_WINDOW:
        case TCPOPT_TIMESTAMP:
            needed_space = 3; // 'W' or 'T' + 2 hex digits
            break;
        default:
            ops_string[0] = '\0';
            return NULL; // Unknown option type
        }
        if (ops_index >= OPS_STRING_MAX_LENGTH ||
            needed_space >= OPS_STRING_MAX_LENGTH - ops_index) {
            ops_string[0] = '\0';
            return NULL;
        }

        // CONVERT TCP OPTIONS TO OPS STRING
        if (option_type == TCPOPT_EOL) {
            ops_string[ops_index++] = 'L';
            ops_string[ops_index] = '\0';
            return ops_string;
        } else if (option_type == TCPOPT_NOP) {
            ops_string[ops_index++] = 'N';
        } else if (option_type == TCPOPT_MAXSEG) {
            uint16_t value = ((uint16_t)options[i + 2] << 8) | options[i + 3];
            int written = snprintf(ops_string + ops_index,
                                    OPS_STRING_MAX_LENGTH - ops_index,
                                    "M%X", (unsigned int)value);
            if (written < 0 || (size_t)written >= OPS_STRING_MAX_LENGTH - ops_index) {
                ops_string[0] = '\0';
                return NULL;
            }
            ops_index += (size_t)written;
            i += options[i + 1] - 1; // Move past the option type, length, and value
        } else if (option_type == TCPOPT_WINDOW) {
            int written = snprintf(ops_string + ops_index,
                                    OPS_STRING_MAX_LENGTH - ops_index, 
                                    "W%X", (unsigned int)options[i + 2]);
            if (written < 0 || (size_t)written >= OPS_STRING_MAX_LENGTH - ops_index) {
                ops_string[0] = '\0';
                return NULL;
            }
            ops_index += (size_t)written;
            i += options[i + 1] - 1; // Move past the option type, length, and value
        } else if (option_type == TCPOPT_SACK_PERMITTED) {
            ops_string[ops_index++] = 'S';
            i += options[i + 1] - 1; // Move past the option type, length, and value
        } else if (option_type == TCPOPT_TIMESTAMP) {
            uint32_t tsval;
            uint32_t tsecr;
            memcpy(&tsval, &options[i + 2], sizeof(tsval));
            memcpy(&tsecr, &options[i + 6], sizeof(tsecr));
            ops_string[ops_index++] = 'T';
            ops_string[ops_index++] = tsval == 0 ? '0' : '1';
            ops_string[ops_index++] = tsecr == 0 ? '0' : '1';
            i += options[i + 1] - 1; // Move past the option type, length, and value
        }
        ops_string[ops_index] = '\0';
    }
    return ops_string;
}

int calculate_ops_test(struct tcp_probe_res *probes, char ops[SEQ_PROBE_COUNT][OPS_STRING_MAX_LENGTH]) {
    if (probes == NULL || ops == NULL) {
        return -1;
    }
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        ops[i][0] = '\0';
    }
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (probes[i].status != PROBE_RECEIVED) {
            ops[i][0] = '$'; // Indicate that the probe was not received
            ops[i][1] = '\0';
            continue;
        }
        if (generate_ops_string(probes[i].response.app_protocol.tcp_ap.options,
                                probes[i].response.app_protocol.tcp_ap.options_len, ops[i]) == NULL) {
            return -1;
        }
    }
    return 1;
}

int calculate_win_test(struct tcp_probe_res *probes, uint16_t win[SEQ_PROBE_COUNT]) {
    if (probes == NULL || win == NULL) {
        return -1;
    }
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        win[i] = probes[i].status == PROBE_RECEIVED ? 
            probes[i].response.app_protocol.tcp_ap.win_size : 0; // indicate the probes was not received with a zero value
    }
    return 1;
}

int calculate_t1_test(struct tcp_probe_res *probes, struct tcp_fingerprint *tcp_fingerprint) {
    if (probes == NULL || tcp_fingerprint == NULL) {
        return -1;
    }

    *tcp_fingerprint = (struct tcp_fingerprint){0};

    // R (Received) test and DF (Don't Fragment) test
    tcp_fingerprint->R_test = probes[0].status == PROBE_RECEIVED;
    if (!tcp_fingerprint->R_test) {
        return 0; // return 0 to indicate that the R test failed
    }
    tcp_fingerprint->DF_test = (probes[0].response.ip_fragoff & IP_DF) != 0;

    // TG (TTL guess) test
    uint8_t ttl = probes[0].response.ip_ttl;
    if (ttl <= 32) {
        tcp_fingerprint->TG_test = 32;
    } else if (ttl <= 64) {
         tcp_fingerprint->TG_test = 64;
    } else if (ttl <= 128) {
        tcp_fingerprint->TG_test = 128;
    } else {
        tcp_fingerprint->TG_test = 255;
    }

    // Q (Quirks) test
    uint8_t flags = probes[0].response.app_protocol.tcp_ap.flags;
    bool reserved_quirk = probes[0].response.app_protocol.tcp_ap.reserved != 0;
    bool urgent_quirk = probes[0].response.app_protocol.tcp_ap.urg_pointer != 0 &&
                        !(flags & TH_URG);
    if (reserved_quirk && urgent_quirk) {
        strcpy(tcp_fingerprint->Q_test, "RU");
    } else if (reserved_quirk) {
        strcpy(tcp_fingerprint->Q_test, "R");
    } else if (urgent_quirk) {
        strcpy(tcp_fingerprint->Q_test, "U");
    } else {
        strcpy(tcp_fingerprint->Q_test, ""); // No quirks
    }

    // S (Sequence) test and A (Acknowledgment) test
    uint32_t received_seq = probes[0].response.app_protocol.tcp_ap.seq;
    uint32_t received_ack = probes[0].response.app_protocol.tcp_ap.ack;
    uint32_t sent_seq = probes[0].probe_sent.seq_num;
    uint32_t sent_ack = probes[0].probe_sent.ack_num;
    if (received_seq == 0) {
        strcpy(tcp_fingerprint->S_test, "Z");
    } else if (received_seq == sent_ack) {
        strcpy(tcp_fingerprint->S_test, "A");
    } else if (received_seq == (uint32_t)(sent_ack + 1u)) {
        strcpy(tcp_fingerprint->S_test, "A+");
    } else {
        strcpy(tcp_fingerprint->S_test, "O");
    }
    if (received_ack == 0) {
        strcpy(tcp_fingerprint->A_test, "Z");
    } else if (received_ack == sent_seq) {
        strcpy(tcp_fingerprint->A_test, "S");
    } else if (received_ack == (uint32_t)(sent_seq + 1u)) {
        strcpy(tcp_fingerprint->A_test, "S+");
    } else {
        strcpy(tcp_fingerprint->A_test, "O");
    }

    // F (Flags) test
    if (flags & 0x40u) strcat(tcp_fingerprint->F_test, "E"); // ECN-Echo
    if (flags & TH_URG) strcat(tcp_fingerprint->F_test, "U");
    if (flags & TH_ACK) strcat(tcp_fingerprint->F_test, "A");
    if (flags & TH_PUSH) strcat(tcp_fingerprint->F_test, "P");
    if (flags & TH_RST) strcat(tcp_fingerprint->F_test, "R");
    if (flags & TH_SYN) strcat(tcp_fingerprint->F_test, "S");
    if (flags & TH_FIN) strcat(tcp_fingerprint->F_test, "F");

    // RD (RST Data) test
    size_t payload_len = probes[0].response.app_protocol.tcp_ap.payload_len;
    if ((flags & TH_RST) && payload_len > 0) {
        const uint8_t *payload = probes[0].response.app_protocol.tcp_ap.payload;
        if (payload == NULL || payload_len > UINT16_MAX) {
            return -1;
        }
        uLong initial = crc32(0L, Z_NULL, 0); // Initialize CRC32
        tcp_fingerprint->RD_test = (uint32_t)crc32_z(initial, payload, payload_len);
    }
    return 1;
}

struct os_fingerprint calculate_os_fingerprint(struct tcp_probe_res *probes)
{
    struct os_fingerprint fingerprint = {0};
    if (probes == NULL) {
        return fingerprint; // The valid field will remain false, indicating an invalid fingerprint
    }
    if (calculate_seq_fingerprint(probes, &fingerprint.seq) < 0 ||
        calculate_ops_test(probes, fingerprint.ops) < 0 ||
        calculate_win_test(probes, fingerprint.win) < 0 ||
        calculate_t1_test(probes, &fingerprint.tcp[0]) < 0) {
        return fingerprint; // The valid field will remain false, indicating an invalid fingerprint
    }
    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        fingerprint.ops_present[i] = probes[i].status == PROBE_RECEIVED;
        fingerprint.win_present[i] = probes[i].status == PROBE_RECEIVED;
    }
    fingerprint.valid = true;
    return fingerprint;
}
