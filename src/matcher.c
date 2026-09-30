#include "matcher.h"

// heper function to parse a hex value from a string. Returns 0 on success, -1 on failureint parse_hex_value(const char *text, uint32_t *out);

const struct fingerprint_group *find_group(const struct match_fingerprint *fingerprint, const char *group_name) {
    if (fingerprint == NULL || group_name == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < fingerprint->group_count; i++) {
        if (strcmp(fingerprint->groups[i].name, group_name) == 0) {
            return &fingerprint->groups[i];
        }
    }
    return NULL;
}

const struct fingerprint_field *find_field(const struct fingerprint_group *group, const char *field_name) {
    if (group == NULL || field_name == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < group->field_count; i++) {
        if (strcmp(group->fields[i].name, field_name) == 0) {
            return &group->fields[i];
        }
    }
    return NULL;
}
/**
 * Finds the match weight for a given group and field name.
 * Returns 1 if found, 0 if not found, and -1 on error.
 */
static int find_match_weight(const struct match_weights *weights, const char *group_name,
                            const char *field_name, unsigned int *points) {
    if (weights == NULL || group_name == NULL || field_name == NULL || points == NULL) {
        return -1;
    }

    for (size_t i = 0; i < weights->weight_count; i++) {
        if (strcmp(weights->weights[i].group_name, group_name) == 0 &&
            strcmp(weights->weights[i].field_name, field_name) == 0) {
            *points = weights->weights[i].points;
            return 1;
        }
    }
    return 0;
}

/* Convert one hexadecimal digit. */
static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/**
 * Parse a hexadecimal substring without requiring a terminating '\0'.
 * Returns 0 on success, -1 on invalid input or overflow. 
*/
static int parse_hex_slice(const char *text, size_t length, uint32_t *out) {
    if (length == 0) {
        return -1;
    }

    uint32_t value = 0;

    for (size_t i = 0; i < length; i++) {
        int digit = hex_digit((unsigned char)text[i]);

        if (digit < 0 || value > (UINT32_MAX - (uint32_t)digit) / 16u) {
            return -1;
        }
        value = value * 16u + (uint32_t)digit;
    }

    *out = value;
    return 0;
}


int match_expression_slice( const char *observed, size_t observed_len, const char *expression, size_t expression_len, bool tcp_options);
/**
 * Helper function that checks a match between an observed value and a reference expression slices. 
 * Which is called recursively by match_expression_slice. 
 * Returns 1 for match, 0 for mismatch, -1 for invalid/unsupported expression.
 */
static int match_helper(const char *observed, size_t observed_len, const char *expression, size_t expression_len, bool tcp_options) {
    if (expression_len == 0) {
        return observed_len == 0;
    }

    if (tcp_options && memchr(expression, '[', expression_len) != NULL) {
        size_t o = 0;
        size_t e = 0;

        while (e < expression_len) {
            if (expression[e] != '[') {
                if (o >= observed_len || observed[o] != expression[e]) {
                    return 0;
                }

                o++;
                e++;
                continue;
            }

            size_t end = e + 1;
            while (end < expression_len && expression[end] != ']') {
                end++;
            }

            if (end == expression_len || end == e + 1) {
                fprintf(stderr, "Invalid expression: unmatched '[' or empty brackets\n");
                return -1;
            }

            size_t number_start = o;

            while (o < observed_len && hex_digit((unsigned char)observed[o]) >= 0) {
                o++;
            }

            if (o == number_start) {
                return 0;
            }

            int result = match_expression_slice(observed + number_start, o - number_start, expression + e + 1, end - e - 1, false);

            if (result != 1) {
                return result;
            }

            e = end + 1;
        }

        return o == observed_len;
    }

    // Check for simple comparison operators at the start of the expression
    if (expression[0] == '<' || expression[0] == '>') {
        uint32_t limit;
        uint32_t value;

        if (parse_hex_slice(expression + 1, expression_len - 1, &limit) < 0) {
            return -1;
        }

        if (parse_hex_slice(observed, observed_len, &value) < 0) {
            return 0;
        }

        return expression[0] == '<' ? value < limit : value > limit;
    }

    // Range check for expressions like "1-A"
    char *dash = memchr(expression, '-', expression_len);

    if (dash != NULL) {
        size_t left_len = (size_t)(dash - expression);
        uint32_t lower, upper, value;

        if (parse_hex_slice(expression, left_len, &lower) < 0 ||
            parse_hex_slice(dash + 1, expression_len - left_len - 1, &upper) < 0 ||
            lower > upper) {
            return -1;
        }

        if (parse_hex_slice(observed, observed_len, &value) < 0) {
            return 0;
        }

        return value >= lower && value <= upper;
    }

    // Unsupported operators.
    if (memchr(expression, '~', expression_len) != NULL ||
        memchr(expression, '<', expression_len) != NULL ||
        memchr(expression, '>', expression_len) != NULL) {
        return -1;
    }

    // Compare the observed value and the expression literally
    if (!tcp_options) {
        uint32_t value, expected;

        if (parse_hex_slice(observed, observed_len, &value) == 0 &&
            parse_hex_slice(expression, expression_len, &expected) == 0) {
            return value == expected;
        }
    }

    // if tcp_options is true, we compare the observed value and the expression literally as strings
    return observed_len == expression_len && memcmp(observed, expression, observed_len) == 0;
}

/**
 * The function gets the expressions between the '|' characters and calls match_helper for each expression.
 * If any of the expressions match, it returns 1. If none match, it returns 0. If any expression is invalid, it returns -1.
 */
int match_expression_slice( const char *observed, size_t observed_len, const char *expression, size_t expression_len, bool tcp_options) {
    size_t start = 0;
    bool inside_brackets = false;
    bool matched = false;

    for (size_t i = 0; i <= expression_len; i++) {
        if (i < expression_len) {
            char c = expression[i];

            if (c == '[') {
                if (!tcp_options || inside_brackets) {
                    fprintf(stderr, "Invalid expression: unexpected '[' at position %zu\n", i);
                    return -1;
                }
                inside_brackets = true;
                continue;
            }

            if (c == ']') {
                if (!inside_brackets) {
                    fprintf(stderr, "Invalid expression: unexpected ']' at position %zu\n", i);
                    return -1;
                }
                inside_brackets = false;
                continue;
            }

            if (c != '|' || inside_brackets) {
                continue;
            }
        }

        if (inside_brackets) {
            fprintf(stderr, "Invalid expression: unmatched '['\n");
            return -1;
        }

        int result = match_helper(observed, observed_len, expression + start, i - start, tcp_options);

        if (result < 0) {
            fprintf(stderr, "Invalid expression: error matching expression slice '%.*s'\n", (int)(i - start), expression + start);
            return -1;
        }
        if (result == 1) {
            matched = true;
        }
        if (i < expression_len) {
            start = i + 1;
        }
    }

    return matched ? 1 : 0;
}

int match_expression(const char *observed, const char *expression, bool tcp_options) {
    if (observed == NULL || expression == NULL) {
        return -1;
    }

    size_t observed_len = strlen(observed);
    size_t expression_len = strlen(expression);

    return match_expression_slice(observed, observed_len, expression, expression_len, tcp_options);
}


/**
 * Compares the fingerprints of the observed and reference systems.
 * Returns 0 on success, -1 on error.
 */
static int compare_fingerprints(const struct match_fingerprint *observed, const struct match_fingerprint *reference, const struct match_weights *weights, struct os_match *out) {

    if (observed == NULL || reference == NULL || weights == NULL || out == NULL) {
        return -1;
    }

    struct os_match res = {0};

    for (size_t i = 0; i < observed->group_count; i++) {
        const struct fingerprint_group *obs_group = &observed->groups[i];
        const struct fingerprint_group *ref_group = find_group(reference, obs_group->name);
        if (ref_group == NULL) {
            continue;
        }

        for (size_t j = 0; j < ref_group->field_count; j++) {
            const struct fingerprint_field *ref_field = &ref_group->fields[j];
            const struct fingerprint_field *obs_field = find_field(obs_group, ref_field->name);
            if (obs_field == NULL) {
                continue;
            }

            unsigned int points = 0;
            int found = find_match_weight(weights, obs_group->name, obs_field->name, &points);
            if (found != 1) {
                fprintf(stderr, "Failed to find match weight for group: %s, field: %s\n", obs_group->name, obs_field->name);
                return -1;
            }

            if (points == 0) {
                continue;
            }

            bool tcp_options = strcmp(obs_group->name, "OPS") == 0 || strcmp(obs_field->name, "O") == 0;

            int matched = match_expression(obs_field->value, ref_field->value, tcp_options);

            if (matched < 0) {
                fprintf(stderr, "Invalid expression for group: %s, field: %s\n", obs_group->name, obs_field->name);
                return -1;
            }

            res.compared_fields++;
            res.possible_points += points; 

            if (matched == 1) {
                res.matched_points += points;
            } 
        }
    }

    res.score = (res.possible_points == 0 ? 0.0 : (double)res.matched_points / res.possible_points);

    *out = res;
    return 0;
}


/**
 * Retains the best match in the best_matches array based on the score of the candidate.
 * If the candidate's score is higher than the lowest score in the best_matches array, it
 * replaces the lowest score with the candidate. 
 * returns 0 on success, -1 on error.
 */
static int retain_best_match(struct os_match *best_matches, size_t *match_count, size_t max_matches, const char *os_name, const struct os_match *candidate) {
    if (best_matches == NULL || match_count == NULL ||
        os_name == NULL || candidate == NULL ||
        max_matches == 0 || *match_count > max_matches) {
        return -1;
    }

    if (candidate->possible_points == 0) {
        return 0;
    }

    size_t count = *match_count;
    size_t existing = count;

    // Check whether this OS name is already in the results
    for (size_t i = 0; i < count; i++) {
        if (strcmp(best_matches[i].os_name, os_name) == 0) {
            if (best_matches[i].score >= candidate->score) {
                return 0;
            }

            existing = i;
            break;
        }
    }

    // A new name must beat the lowest score when the array is full
    if (existing == count && count == max_matches &&
        candidate->score <= best_matches[count - 1].score) {
        return 0;
    }

    // Allocate before modifying the array
    struct os_match retained = *candidate;
    retained.os_name = strdup(os_name);
    if (retained.os_name == NULL) {
        return -1;
    }

    if (existing < count) {
        // remove the existing entry to make room for the new one for the same os name
        free(best_matches[existing].os_name);

        for (size_t i = existing; i + 1 < count; i++) {
            best_matches[i] = best_matches[i + 1];
        }

        count--;
        best_matches[count] = (struct os_match){0};
    } else if (count == max_matches) {
        // remove the lowest-scoring result to make room for the new one
        count--;
        free(best_matches[count].os_name);
        best_matches[count] = (struct os_match){0};
    }

    // find position to insert the new result, keeping the array sorted by score in descending order
    size_t position = 0;

    while (position < count && best_matches[position].score >= retained.score) {
        position++;
    }

    // move the lower-scoring results down to make room for the new result
    for (size_t i = count; i > position; i--) {
        best_matches[i] = best_matches[i - 1];
    }

    best_matches[position] = retained;
    *match_count = count + 1;

    return 0;
}

int find_os_matches(const char *database_path, const char *observed_fingerprint_string, struct os_match *best_matches, const size_t max_matches, size_t *match_count) {
    if (database_path == NULL || observed_fingerprint_string == NULL || best_matches == NULL || match_count == NULL) {
        return -1;
    }
    
    *match_count = 0;

    FILE *file = fopen(database_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Failed to open database file\n");
        return -1;
    }

    struct match_fingerprint observed = {0};
    if (parse_observed_fingerprint(observed_fingerprint_string, &observed) != 0) {
        fprintf(stderr, "Failed to parse observed fingerprint\n");
        fclose(file);
        return -1;
    }

    struct match_weights weights = {0};
    if (read_match_weights(file, &weights) != 0) {
        fprintf(stderr, "Failed to read MatchPoints\n");
        fclose(file);
        return -1;
    }


    if (max_matches == 0 ||
        max_matches > SIZE_MAX / sizeof(struct os_match)) {
        fprintf(stderr, "Invalid maximum match count\n");
        return EXIT_FAILURE;
    }
    if (observed.group_count == 0) {
        fprintf(stderr, "Observed fingerprint has no groups\n");
        return EXIT_FAILURE;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to rewind database file\n");
        fclose(file);
        return -1;
    }

    struct database_entry entry = {0};

    int status;
    while ((status = read_next_reference(file, &entry)) == 1) {
        struct os_match candidate = {0};

        if (compare_fingerprints(&observed, &entry.fingerprint, &weights, &candidate) != 0) {
            fprintf(stderr, "Skipping reference that could not be compared: %s\n", entry.os_name);

            free_database_entry(&entry);
            continue;
        }

        if (retain_best_match(best_matches, match_count, max_matches, entry.os_name, &candidate) != 0) {
            fprintf(stderr, "Failed to retain match\n");
            free_database_entry(&entry);
            free_match_weights(&weights);
            fclose(file);
            if (*match_count > 0) {
                free_os_matches(best_matches, *match_count);
                *match_count = 0;
            }
            return -1;
        }

        free_database_entry(&entry);
    }

    if (status < 0) {
        fprintf(stderr, "Failed to parse databse reference.\n");
        free_match_weights(&weights);
        fclose(file);
        if (*match_count > 0) {
            free_os_matches(best_matches, *match_count);
            *match_count = 0;
        }
        return -1;
    }

    free_match_weights(&weights);
    fclose(file);
    return 0;
}


void free_os_matches(struct os_match *matches, size_t match_count) {
    if (matches == NULL) {
        return;
    }

    for (size_t i = 0; i < match_count; i++) {
        free(matches[i].os_name);
        matches[i] = (struct os_match){0};
    }
}
