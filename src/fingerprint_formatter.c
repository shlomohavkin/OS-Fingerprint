#include "fingerprint_formatter.h"

/**
 * Useful helper function to append formatted text to a buffer while keeping track of the used space.
 * @param buffer The buffer to which the formatted text will be appended.
 * @param capacity The total capacity of the buffer.
 * @param used A pointer to the variable that keeps track of the used space in the buffer.
 * @param format The format string (like printf).
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int append_text(char *buffer, size_t capacity, size_t *used, const char *format,...) {
    if (*used >= capacity) {
        return -1;
    }

    va_list args;
    va_start(args, format);

    int written = vsnprintf(buffer + *used, capacity - *used, format, args);

    va_end(args);

    if (written < 0 || (size_t)written >= capacity - *used) {
        return -1;
    }

    *used += (size_t)written;
    return 0;
}

/**
 * Helper function to format the U1 test value into a string representation,
 * and save it in the provided buffer.
 */
static void format_u1_value(struct u1_val value, char text[5]) {
    if (value.is_good) {
        strcpy(text, "G");
    } else {
        snprintf(text, 5, "%X", (unsigned int)value.value);
    }
}

/**
 * Helper function to format the IP ID test value into a string representation, 
 * and save it in the provided buffer.
 */
static int format_ip_id_value(const struct ip_id_fingerprint *id, char text[5]) {
    switch (id->kind) {
    case IP_ID_UNAVAILABLE:
        text[0] = '\0';
        return 0;

    case IP_ID_ZERO:
        strcpy(text, "Z");
        break;

    case IP_ID_INCREMENTAL:
        strcpy(text, "I");
        break;

    case IP_ID_BROKEN_INCREMENTAL:
        strcpy(text, "BI");
        break;

    case IP_ID_RANDOM_POSITIVE:
        strcpy(text, "RI");
        break;

    case IP_ID_RANDOM:
        strcpy(text, "RD");
        break;

    case IP_ID_CONSTANT:
        if (snprintf(text, 5, "%X", (unsigned int)id->constant_value) < 0) {
            return -1;
        }
        break;

    default:
        return -1;
    }

    return 1;
}

/**
 * Helper function to format the SEQ test values into a string representation.
 * @param fingerprint The OS fingerprint containing the SEQ test values.
 * @param buffer The buffer where the formatted string will be stored.
 * @param capacity The total capacity of the buffer.
 * @param used A pointer to the variable that keeps track of the used space in the buffer.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_seq(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    if (fingerprint == NULL || buffer == NULL ||
        capacity == 0 || used == NULL || *used >= capacity) {
        return -1;
    }

    const struct seq_fingerprint *seq = &fingerprint->seq;
    bool first = true;

    // SP, GCD, ISR
    if (seq->metrics_present) {
        if (append_text(buffer, capacity, used,
                        "SEQ(SP=%" PRIX32 "%%GCD=%" PRIX32 "%%ISR=%" PRIX32,
                        seq->sp, seq->gcd, seq->isr) < 0) {
            return -1;
        }

        first = false;
    }

    // TI, CI, II
    const struct ip_id_fingerprint *ids[] = {&seq->ti, &seq->ci, &seq->ii};
    const char *names[] = {"TI", "CI", "II"};

    for (size_t i = 0; i < 3; i++) {
        char value[5];
        int status = format_ip_id_value(ids[i], value);

        if (status < 0) {
            return -1;
        }
        if (status == 0) {
            continue;
        }

        if (append_text(buffer, capacity, used,
                        "%s%s=%s",
                        first ? "SEQ(" : "%", 
                        names[i], value) < 0) {
            return -1;
        }

        first = false;
    }

    // SS
    if (seq->ss != SHARED_SEQUENCE_UNAVAILABLE) {
        if (append_text(buffer, capacity, used,
                        "%sSS=%c",
                        first ? "SEQ(" : "%",
                        seq->ss == SHARED_SEQUENCE_SAME ? 'S' : 'O') < 0) {
            return -1;
        }

        first = false;
    }

    // TS
    char ts_value[9]; // Eight hex digits for uint32_t + '\0'.

    switch (seq->ts.kind) {
    case TIMESTAMP_UNAVAILABLE:
        ts_value[0] = '\0';
        break;
    case TIMESTAMP_UNSUPPORTED:
        strcpy(ts_value, "U");
        break;
    case TIMESTAMP_ZERO:
        strcpy(ts_value, "0");
        break;
    case TIMESTAMP_RATE:
        if (snprintf(ts_value, sizeof(ts_value), "%" PRIX32, seq->ts.encoded_rate) < 0) {
            return -1;
        }
        break;
    default:
        return -1;
    }

    if (ts_value[0] != '\0') {
        if (append_text(buffer, capacity, used,
                        "%sTS=%s",
                        first ? "SEQ(" : "%",
                        ts_value) < 0) {
            return -1;
        }

        first = false;
    }

    if (!first) {
        return append_text(buffer, capacity, used, ")\n");
    }

    return 0; // No available fields: omit the entire SEQ line.
}

/**
 * Helper function to format the OPS test values into a string representation.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_ops(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    bool first = true;

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (!fingerprint->ops_present[i]) {
            continue;
        }

        if (append_text(buffer, capacity, used, "%sO%zu=%s", first ? "OPS(" : "%", i + 1, fingerprint->ops[i]) < 0) {
            return -1;
        }
        first = false;
    }

    if (!first) {
        return append_text(buffer, capacity, used, ")\n");
    }

    return 0; // No available window results: omit OPS.
}

/**
 * Helper function to format the WIN test values into a string representation.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_win(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    bool first = true;

    for (size_t i = 0; i < SEQ_PROBE_COUNT; i++) {
        if (!fingerprint->win_present[i]) {
            continue;
        }

        if (append_text(buffer, capacity, used, "%sW%zu=%X", first ? "WIN(" : "%", i + 1, (unsigned int)fingerprint->win[i]) < 0) {
            return -1;
        }
        first = false;
    }

    if (!first) {
        return append_text(buffer, capacity, used, ")\n");
    }

    return 0; // No available window results: omit WIN.
}

/**
 * Helper function to format the T1–T7 test values into a string representation.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_t1_7(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    for (size_t i = 0; i < TX_COUNT + 1; i++) {
        const struct tcp_fingerprint *tcp = &fingerprint->tcp[i];
        const struct tcp_common_fingerprint *common = &tcp->common;

        if (!common->R_test) {
            if (append_text(buffer, capacity, used,
                            "T%zu(R=N)\n", i + 1) < 0) {
                return -1;
            }
            continue;
        }

        if (append_text(buffer, capacity, used, 
                        "T%zu(R=Y%%DF=%c%%%s=%X",
                        i + 1,
                        common->DF_test ? 'Y' : 'N',
                        common->T_present ? "T" : "TG",
                        (unsigned int)(common->T_present ? common->T_test : common->TG_test)) < 0) {
            return -1;
        }

        // W is included only for T2–T7.
        if (i != 0 && append_text(buffer, capacity, used, "%%W=%X", (unsigned int)common->W_test) < 0) {
            return -1;
        }

        if (append_text(buffer, capacity, used, 
                        "%%S=%s%%A=%s%%F=%s",
                        tcp->S_test, tcp->A_test, tcp->F_test) < 0) {
            return -1;
        }

        // O is included only for T2–T7.
        if (i != 0 &&
            append_text(buffer, capacity, used, "%%O=%s", common->O_test) < 0) {
            return -1;
        }

        if (append_text(buffer, capacity, used,
                        "%%RD=%" PRIX32 "%%Q=%s)\n",
                        tcp->RD_test, common->Q_test) < 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * Helper function to format the ECN test values into a string representation.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_ecn(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    const struct ecn_fingerprint *ecn = &fingerprint->ecn;
    const struct tcp_common_fingerprint *common = &ecn->common;

    if (!common->R_test) {
        return append_text(buffer, capacity, used, "ECN(R=N)\n");
    }

    return append_text(buffer, capacity, used,
                        "ECN(R=Y%%DF=%c%%%s=%X%%W=%X%%O=%s%%CC=%s%%Q=%s)\n",
                        common->DF_test ? 'Y' : 'N',
                        common->T_present ? "T" : "TG",
                        (unsigned int)(common->T_present ? common->T_test : common->TG_test),
                        (unsigned int)common->W_test,
                        common->O_test,
                        ecn->CC_test,
                        common->Q_test);
}

/**
 * Helper function to format the IE test values into a string representation.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_ie(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    const struct ie_fingerprint *ie = &fingerprint->ie;

    if (!ie->R_test) {
        return append_text(buffer, capacity, used, "IE(R=N)\n");
    } 
    if (append_text(buffer, capacity, used,
                    "IE(R=Y%%DFI=%s%%%s=%X%%CD=%s)\n",
                    ie->DFI_test,
                    ie->T_present ? "T" : "TG",
                    (unsigned int)(ie->T_present ? ie->T_test : ie->TG_test),
                    ie->CD_test) < 0) {
        return -1;
    }

    return 0;
}

/**
 * Helper function to format the U1 test values into a string representation.
 * @return 0 on success, -1 on error (e.g., if the buffer is too small to hold the formatted text).
 */
static int format_u1(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity, size_t *used) {
    const struct u1_fingerprint *u1 = &fingerprint->u1;

    if (!u1->R_test) {
        return append_text(buffer, capacity, used, "U1(R=N)\n");
    }

    char ripl[5], rid[5], ruck[5];

    format_u1_value(u1->RIPL_test, ripl);
    format_u1_value(u1->RID_test, rid);
    format_u1_value(u1->RUCK_test, ruck);

    return append_text(buffer, capacity, used,
                        "U1(R=Y%%DF=%c%%%s=%X%%IPL=%X%%UN=%" PRIX32 "%%RIPL=%s%%RID=%s%%RIPCK=%c%%RUCK=%s%%RUD=%c)\n",
                        u1->DF_test ? 'Y' : 'N',
                        u1->T_present ? "T" : "TG",
                        (unsigned int)(u1->T_present ? u1->T_test : u1->TG_test),
                        (unsigned int)u1->IPL_test,
                        u1->UN_test,
                        ripl,
                        rid,
                        u1->RIPCK_test,
                        ruck,
                        u1->RUD_test ? 'G' : 'I');
}


/**
 * Main function to format the OS fingerprint into a string representation.
 * @param fingerprint The OS fingerprint to format.
 * @param buffer The buffer where the formatted string will be stored.
 * @return The number of characters written to the buffer (excluding the null terminator) 
 * if successful, or -1 on error (e.g., if the buffer is too small to hold the 
 */
int format_os_fingerprint(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity) {
    if (fingerprint == NULL || buffer == NULL || capacity == 0) {
        return -1;
    }

    buffer[0] = '\0';
    size_t used = 0;

    if (format_seq(fingerprint, buffer, capacity, &used) < 0 ||
        format_ops(fingerprint, buffer, capacity, &used) < 0 ||
        format_win(fingerprint, buffer, capacity, &used) < 0 ||
        format_ecn(fingerprint, buffer, capacity, &used) < 0 ||
        format_t1_7(fingerprint, buffer, capacity, &used) < 0 || 
        format_u1(fingerprint, buffer, capacity, &used) < 0 ||
        format_ie(fingerprint, buffer, capacity, &used) < 0) {
        fprintf(stderr, "Failed to format fingerprint\n");
        buffer[0] = '\0'; // Discard the incomplete fingerprint.
        return -1;
    }

    return (int)used; // Number of characters, excluding '\0'.
}