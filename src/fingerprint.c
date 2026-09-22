#include "fingerprint.h"
#include <stdlib.h>

uint32_t diffs[5] = {0};
uint32_t seq_rates[5] = {0};


uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
uint32_t gcd_array(uint32_t *arr, size_t len) {
    if (arr == NULL || len == 0) {
        fprintf(stderr, "Invalid arguments to gcd_array\n");
        return 0;
    }

    uint32_t result = arr[0];
    for (size_t i = 1; i < len; ++i) {
        result = gcd(result, arr[i]);
        if (result == 1) {
            break; // GCD is 1, no need to continue
        }
    }
    return result;
}
uint32_t standard_deviation(uint32_t *arr, size_t len) {
    if (arr == NULL || len < 2) {
        fprintf(stderr, "Invalid arguments to standard_deviation\n");
        return 0;
    }

    double avg = 0.0;
    for (size_t i = 0; i < len; ++i) {
        avg += arr[i];
    }
    avg /= len;

    double var = 0.0;
    for (size_t i = 0; i < len; ++i) {
        var += (arr[i] - avg) * (arr[i] - avg);
    }
    var /= len;

    return (uint32_t)sqrt(var);
}

uint32_t calculate_gcd_test(struct tcp_probe_res *tcp_probe_res) {
    if (tcp_probe_res == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_gcd\n");
        return 0;
    }

    for (size_t i = 0; i < 5; ++i) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED || tcp_probe_res[i + 1].status != PROBE_RECEIVED) {
            fprintf(stderr, "Insufficient received probes to calculate GCD\n");
            return 0;
        }

        if (tcp_probe_res[i + 1].response.app_protocol.tcp_ap.seq < tcp_probe_res[i].response.app_protocol.tcp_ap.seq) {
            uint32_t opt1 = tcp_probe_res[i + 1].response.app_protocol.tcp_ap.seq - tcp_probe_res[i].response.app_protocol.tcp_ap.seq;
            uint32_t opt2 = (uint32_t)(UINT32_MAX - tcp_probe_res[i].response.app_protocol.tcp_ap.seq + tcp_probe_res[i + 1].response.app_protocol.tcp_ap.seq + 1);
            diffs[i] = (opt1 < opt2) ? opt1 : opt2;
        } else {
            diffs[i] = tcp_probe_res[i + 1].response.app_protocol.tcp_ap.seq - tcp_probe_res[i].response.app_protocol.tcp_ap.seq;
        }

    }
    return gcd_array(diffs, 5);
}


uint32_t calculate_isr_test(struct tcp_probe_res *tcp_probe_res) {
    if (tcp_probe_res == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_gcd\n");
        return 0;
    }

    for (size_t i = 0; i < 5; ++i) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED || tcp_probe_res[i + 1].status != PROBE_RECEIVED) {
            fprintf(stderr, "Insufficient received probes to calculate ISR\n");
            return 0;
        }
        seq_rates[i] = diffs[i] / (uint32_t)(tcp_probe_res[i + 1].sent_at.tv_sec - tcp_probe_res[i].sent_at.tv_sec);
    }

    double avg_seq_rate = 0;
    for (size_t i = 0; i < 5; ++i) {
        avg_seq_rate += seq_rates[i];
    }
    avg_seq_rate /= 5;

    return avg_seq_rate < 1.0f ? 0 : (uint32_t)round(8.0 * log2(avg_seq_rate)); 
}

uint32_t calculate_sp_test(struct tcp_probe_res *tcp_probe_res, size_t num_probes, uint32_t gcd_test) {
    if (tcp_probe_res == NULL || gcd_test == 0 || num_probes < 4 || num_probes > 6) {
        fprintf(stderr, "Invalid arguments to calculate_sp_test\n");
        return 0;
    }

    uint32_t sp_values[num_probes - 1];
    for (size_t i = 0; i < num_probes - 1; i++) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED || tcp_probe_res[i + 1].status != PROBE_RECEIVED) {
            continue;
        }
        sp_values[i] = gcd_test > 9 ? seq_rates[i] / gcd_test : seq_rates[i];
    }

    return standard_deviation(sp_values, num_probes - 1) < 1.0f ? 
            0 : 
            (uint32_t)round(8.0 * log2(standard_deviation(sp_values, num_probes - 1)));
}

struct ip_id_fingerprint calculate_ip_id_fingerprints_ti(struct tcp_probe_res *tcp_probe_res, size_t num_probes) {
    if (tcp_probe_res == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_ip_id_fingerprints_ti\n");
        return (struct ip_id_fingerprint){.kind = IP_ID_UNAVAILABLE, .constant_value = 0};
    }
    if (num_probes < 3) {
        fprintf(stderr, "Insufficient probes to calculate TI IP ID test\n");
        return (struct ip_id_fingerprint){.kind = IP_ID_UNAVAILABLE, .constant_value = 0};
    }
    bool is_zero = true;
    for (size_t i = 0; i < num_probes; i++) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED) {
            continue;
        }
        if (tcp_probe_res[i].response.ip_id != 0) {
            is_zero = false;        }
    }
    if (is_zero) {
        return (struct ip_id_fingerprint){.kind = IP_ID_ZERO, .constant_value = 0};
    }

    bool is_identical = true;
    bool is_broken_incremental = true;
    bool is_incremental = true;
    uint16_t diff = 0;
    for (size_t i = 0; i < num_probes - 1; i++) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED || tcp_probe_res[i + 1].status != PROBE_RECEIVED) {
            continue;
        }

        diff = (uint16_t)(tcp_probe_res[i + 1].response.ip_id - tcp_probe_res[i].response.ip_id);
        if (diff != 0) {
            is_identical = false;
        }
        if (diff >= 20000) {
            return (struct ip_id_fingerprint){.kind = IP_ID_RANDOM, .constant_value = 0};
        }
        if ((diff % 256 != 0 && diff >= 1000) ||
            (diff % 256 == 0 && diff >= 25600)) {
            return (struct ip_id_fingerprint){.kind = IP_ID_RANDOM_POSITIVE, .constant_value = 0};
        }
        if (!(diff % 256 == 0 && diff <= 5120)) {
            is_broken_incremental = false;
        }
        if (diff > 10) {
            is_incremental = false;
        }
    }

    if (is_identical) {
        return (struct ip_id_fingerprint){.kind = IP_ID_CONSTANT, .constant_value = tcp_probe_res[0].response.ip_id};
    } else if (is_broken_incremental) {
        return (struct ip_id_fingerprint){.kind = IP_ID_BROKEN_INCREMENTAL, .constant_value = 0};
    } else if (is_incremental) {
        return (struct ip_id_fingerprint){.kind = IP_ID_INCREMENTAL, .constant_value = 0};
    }
    return (struct ip_id_fingerprint){.kind = IP_ID_UNAVAILABLE, .constant_value = 0};
}

struct timestamp_fingerprint calculate_timestamp_fingerprint(struct tcp_probe_res *tcp_probe_res, size_t num_probes) {
    if (tcp_probe_res == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_timestamp_fingerprint\n");
        return (struct timestamp_fingerprint){.kind = TIMESTAMP_UNAVAILABLE, .encoded_rate = 0};
    }


    double average_ts_inc_sec = 0;
    for (size_t i = 0; i < num_probes - 1; i++) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED || 
            tcp_probe_res[i].response.app_protocol.tcp_ap.timestamp_present == false) {
            return (struct timestamp_fingerprint){.kind = TIMESTAMP_UNSUPPORTED, .encoded_rate = 0};
        }
        if (tcp_probe_res[i].response.app_protocol.tcp_ap.tsval == 0) {
            return (struct timestamp_fingerprint){.kind = TIMESTAMP_ZERO, .encoded_rate = 0};
        }
        average_ts_inc_sec += (tcp_probe_res[i + 1].response.app_protocol.tcp_ap.tsval - 
                            tcp_probe_res[i].response.app_protocol.tcp_ap.tsval) /
                            (tcp_probe_res[i + 1].sent_at.tv_sec - tcp_probe_res[i].sent_at.tv_sec);
    }
    average_ts_inc_sec /= (num_probes - 1);

    if (average_ts_inc_sec >= 0 && average_ts_inc_sec <= 5.66) {
        return (struct timestamp_fingerprint){.kind = TIMESTAMP_RATE, .encoded_rate = 0x01};
    } else if (average_ts_inc_sec >= 70 && average_ts_inc_sec <= 150) {
        return (struct timestamp_fingerprint){.kind = TIMESTAMP_RATE, .encoded_rate = 0x07};
    } else if (average_ts_inc_sec > 150 && average_ts_inc_sec <= 350) {
        return (struct timestamp_fingerprint){.kind = TIMESTAMP_RATE, .encoded_rate = 0x08};
    } else {
        return (struct timestamp_fingerprint){.kind = TIMESTAMP_RATE, .encoded_rate = round(log2(average_ts_inc_sec))};
    }
}

int calculate_seq_fingerprint(struct tcp_probe_res *tcp_probe_res, struct seq_fingerprint *fingerprint, size_t received_count) {
    fingerprint->gcd = calculate_gcd_test(tcp_probe_res);
    fingerprint->isr = calculate_isr_test(tcp_probe_res);
    fingerprint->sp = calculate_sp_test(tcp_probe_res, received_count, fingerprint->gcd);
    fingerprint->ti = calculate_ip_id_fingerprints_ti(tcp_probe_res, received_count);
    // fingerprint->ii = calculate_ip_id_fingerprints_ii(tcp_probe_res); // after icmp and TX tests implemented
    // fingerprint->ci = calculate_ip_id_fingerprints_ci(tcp_probe_res); // after icmp and TX tests implemented
    // calculate_shared_sequence(tcp_probe_res); // after icmp and TX tests implemented
    fingerprint->ts = calculate_timestamp_fingerprint(tcp_probe_res, received_count);

    return 1;
}



char *generate_ops_string(const uint8_t *options, size_t options_len, char *ops_string) {
    if (ops_string == NULL) {
        fprintf(stderr, "Invalid ops_string buffer\n");
        return NULL;
    }
    ops_string[0] = '\0'; // Initialize the ops_string to an empty string
    if (options_len == 0) {
        return ops_string; // Return an empty string if there are no options
    }

    if (options == NULL || options_len > OPTIONS_MAX_LENGTH) {
        fprintf(stderr, "TCP options length exceeds maximum allowed length or options is NULL\n");
        return NULL;
    }

    size_t ops_index = 0;

    for (size_t i = 0; i < options_len; i++) {
        uint8_t option_type = options[i];

        // CHECKS TO ENSURE VALIDITY OF TCP OPTIONS
        if (option_type != TCPOPT_EOL && option_type != TCPOPT_NOP) {
            if (options_len < i + 2) {
                fprintf(stderr, "TCP options length is too short for option type %u\n", option_type);
                return NULL;
            }

            size_t cur_option_len = options[i + 1];
            if (cur_option_len < 2 || options_len < i + cur_option_len) {
                fprintf(stderr, "Invalid TCP option length for option type %u\n", option_type);
                return NULL;
            }

            if ((option_type == TCPOPT_MAXSEG && cur_option_len != 4) ||
                (option_type == TCPOPT_WINDOW && cur_option_len != 3) ||
                (option_type == TCPOPT_SACK_PERMITTED && cur_option_len != 2) ||
                (option_type == TCPOPT_TIMESTAMP && cur_option_len != 10)) {
                fprintf(stderr, "Unexpected TCP option length for option type %u\n", option_type);
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
                return NULL; // Unknown option type
        }
        
        if (ops_index >= OPS_STRING_MAX_LENGTH || 
            ops_index + needed_space >= OPS_STRING_MAX_LENGTH) {
            fprintf(stderr, "String buffer overflow\n");
            return NULL;
        }

        // CONVERT TCP OPTIONS TO OPS STRING
        if (option_type == TCPOPT_EOL) {
            ops_string[ops_index++] = 'L'; 
            ops_string[ops_index] = '\0'; // Null-terminate the string
            return ops_string;
        } else if (option_type == TCPOPT_NOP) {
            ops_string[ops_index++] = 'N';
        } else if (option_type == TCPOPT_MAXSEG) {
            uint16_t mss_value = ((uint16_t)options[i + 2] << 8) |options[i + 3];     
            int written = snprintf(ops_string + ops_index, OPS_STRING_MAX_LENGTH - ops_index, "M%X", (unsigned int)mss_value);
            if (written < 0 || (size_t)written >= OPS_STRING_MAX_LENGTH - ops_index) {
                fprintf(stderr, "String buffer overflow while writing MSS value\n");
                return NULL;
            }
            ops_index += (size_t)written;       
            i += options[i + 1] - 1; // Move past the option type, length, and value
        } else if (option_type == TCPOPT_WINDOW) {
            uint8_t win_value = (uint8_t)options[i + 2];  
            int written = snprintf(ops_string + ops_index, OPS_STRING_MAX_LENGTH - ops_index, "W%X", (unsigned int)win_value);
            if (written < 0 || (size_t)written >= OPS_STRING_MAX_LENGTH - ops_index) {
                fprintf(stderr, "String buffer overflow while writing Window Scale value\n");
                return NULL;
            }          
            ops_index += (size_t)written;
            i += options[i + 1] - 1; // Move past the option type, length, and value
        } else if (option_type == TCPOPT_SACK_PERMITTED) {
            ops_string[ops_index++] = 'S';
            i += options[i + 1] - 1; // Move past the option type and length
        } else if (option_type == TCPOPT_TIMESTAMP) {
            ops_string[ops_index++] = 'T';
            uint32_t tsval;
            uint32_t tsecr;
            memcpy(&tsval, &options[i + 2], sizeof(tsval));
            memcpy(&tsecr, &options[i + 6], sizeof(tsecr));
            ops_string[ops_index++] = tsval == 0 ? '0' : '1'; // TSval
            ops_string[ops_index++] = tsecr == 0 ? '0' : '1'; // TSecr
            i += options[i + 1] - 1; // Move past the option type
        } else {
            return NULL;
        }
        ops_string[ops_index] = '\0'; // Null-terminate the string

    }

    return ops_string;
}

int calculate_ops_test(struct tcp_probe_res *tcp_probe_res,  char ops[SEQ_PROBE_COUNT][OPS_STRING_MAX_LENGTH]) {
    if (tcp_probe_res == NULL || ops == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_ops_test\n");
        return -1;
    }

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED) {
            ops[i][0] = '$'; // Indicate that the probe was not received
            ops[i][1] = '\0'; // Null-terminate the string
            continue;
        }
        size_t options_len = tcp_probe_res[i].response.app_protocol.tcp_ap.options_len;
        if (options_len > 0) {
            if (options_len > OPTIONS_MAX_LENGTH) {
                fprintf(stderr, "TCP options length exceeds maximum allowed length\n");
                return -1;
            }
            if (generate_ops_string(tcp_probe_res[i].response.app_protocol.tcp_ap.options, options_len, ops[i]) == NULL) {
                return -1;
            }
        } else {
            ops[i][0] = '\0'; // No options present
        }
    }

    return 1;
}

int calculate_win_test(struct tcp_probe_res *tcp_probe_res, uint16_t win[SEQ_PROBE_COUNT]) {
    if (tcp_probe_res == NULL || win == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_win_test\n");
        return -1;
    }

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (tcp_probe_res[i].status != PROBE_RECEIVED) {
            win[i] = 0; // Indicate that the probe was not received
            continue;
        }
        win[i] = tcp_probe_res[i].response.app_protocol.tcp_ap.win_size;
    }

    return 1;
}

int calculate_t1_test(struct tcp_probe_res *tcp_probe_res, struct tcp_fingerprint *tcp_fingerprint) {
    if (tcp_probe_res == NULL || tcp_fingerprint == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_t1_test\n");
        return -1;
    }

    // R (Received) and DF (Don't Fragment) tests
    tcp_fingerprint->R_test = tcp_probe_res[0].status == PROBE_RECEIVED;
    tcp_fingerprint->DF_test = (tcp_probe_res[0].response.ip_fragoff & IP_DF) != 0;

    // TG (TTL guess) test
    if (tcp_probe_res[0].response.ip_ttl < 32) {
        tcp_fingerprint->TG_test = 32;
    } else if (tcp_probe_res[0].response.ip_ttl < 64) {
         tcp_fingerprint->TG_test = 64;
    } else if (tcp_probe_res[0].response.ip_ttl < 128) {
        tcp_fingerprint->TG_test = 128;
    } else if (tcp_probe_res[0].response.ip_ttl < 255) {
        tcp_fingerprint->TG_test = 255;
    } else {
        tcp_fingerprint->TG_test = 0; // Unknown or invalid TTL
    }

    // Q (Quirks)test
    if (tcp_probe_res[0].response.app_protocol.tcp_ap.reserved != 0 &&
        tcp_probe_res[0].response.app_protocol.tcp_ap.urg_pointer != 0) {
        strcpy(tcp_fingerprint->Q_test, "RU\0");
    } else if (tcp_probe_res[0].response.app_protocol.tcp_ap.reserved != 0) {
        strcpy(tcp_fingerprint->Q_test, "R\0");
    } else if (tcp_probe_res[0].response.app_protocol.tcp_ap.urg_pointer != 0) {
        strcpy(tcp_fingerprint->Q_test, "U\0");
    } else {
        tcp_fingerprint->Q_test[0] = '\0'; // No quirks
    }

    // S (Sequence) test
    if (tcp_probe_res[0].response.app_protocol.tcp_ap.seq == 0) {
        strcpy(tcp_fingerprint->S_test, "Z\0");
    } else if (tcp_probe_res[0].response.app_protocol.tcp_ap.seq == tcp_probe_res[0].response.app_protocol.tcp_ap.ack) {
        strcpy(tcp_fingerprint->S_test, "A\0");
    } else if (tcp_probe_res[0].response.app_protocol.tcp_ap.seq == tcp_probe_res[0].response.app_protocol.tcp_ap.ack + 1) {
        strcpy(tcp_fingerprint->S_test, "A+\0");
    } else {
        strcpy(tcp_fingerprint->S_test, "O\0");
    }

    // A (Acknowledgment) test
    if (tcp_probe_res[0].response.app_protocol.tcp_ap.ack == 0) {
        strcpy(tcp_fingerprint->A_test, "Z\0");
    } else if (tcp_probe_res[0].response.app_protocol.tcp_ap.ack == tcp_probe_res[0].response.app_protocol.tcp_ap.seq) {
        strcpy(tcp_fingerprint->A_test, "S\0");
    } else if (tcp_probe_res[0].response.app_protocol.tcp_ap.ack == tcp_probe_res[0].response.app_protocol.tcp_ap.seq + 1) {
        strcpy(tcp_fingerprint->A_test, "S+\0");
    } else {
        strcpy(tcp_fingerprint->A_test, "O\0");
    }

    // F (Flags) test
    uint8_t flags = tcp_probe_res[0].response.app_protocol.tcp_ap.flags;
    char flag_str_res[8] = {0}; // 7 flags + null terminator
    if (flags & 0x40) strcat(flag_str_res, "E"); // ECN-Echo
    if (flags & TH_URG) strcat(flag_str_res, "U");
    if (flags & TH_ACK) strcat(flag_str_res, "A");
    if (flags & TH_PUSH) strcat(flag_str_res, "P");
    if (flags & TH_RST) strcat(flag_str_res, "R");
    if (flags & TH_SYN) strcat(flag_str_res, "S");
    if (flags & TH_FIN) strcat(flag_str_res, "F");
    strncpy(tcp_fingerprint->F_test, flag_str_res, sizeof(tcp_fingerprint->F_test) - 1);
    tcp_fingerprint->F_test[sizeof(tcp_fingerprint->F_test) - 1] = '\0';

    return 1;
}

struct os_fingerprint calculate_os_fingerprint(struct tcp_probe_res *tcp_probe_res) {
    if (tcp_probe_res == NULL) {
        fprintf(stderr, "Invalid arguments to calculate_os_fingerprint\n");
        return (struct os_fingerprint){0};
    }
    
    size_t received_count = 0;
    for (size_t i = 0; i < 6; ++i) {
        if (tcp_probe_res[i].status == PROBE_RECEIVED) {
            received_count++;
        }
    }

    struct os_fingerprint fingerprint = {0};

    calculate_seq_fingerprint(tcp_probe_res, &fingerprint.seq, received_count);
    calculate_ops_test(tcp_probe_res, fingerprint.ops);
    calculate_win_test(tcp_probe_res, fingerprint.win);
    calculate_t1_test(tcp_probe_res, &fingerprint.tcp[0]); // can calculate T1, and then need T2-T7 to implement the rest

    return fingerprint;
}

