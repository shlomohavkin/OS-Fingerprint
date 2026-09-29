#include "matcher.h"

// heper function to parse a uint32_t value from a string with a given base (e.g., 10 for decimal, 16 for hexadecimal).
int parse_uint32_value(const char *text, unsigned int base, uint32_t *out);

const struct fingerprint_group *find_group(const struct match_fingerprint *fingerprint, const char *group_name);

const struct fingerprint_field *find_field(const struct fingerprint_group *group, const char *field_name);

/*  1 = found
 0 = missing
-1 = invalid arguments*/
int find_match_weight(const struct fingerprint_database *database, const char *group_name, 
                    const char *field_name, unsigned int *points);


/*  1 = match
 0 = mismatch
-1 = malformed or unsupported expression*/
int match_expression(const char *observed, const char *reference_expression, bool tcp_options);


/*  1 = match
 0 = mismatch
-1 = error*/
int compare_fingerprints(const struct match_fingerprint *observed,
                        const struct match_fingerprint *reference,
                        const struct fingerprint_database *database,
                        struct os_match *out);


int find_os_matches(const struct match_fingerprint *observed,
                    const struct fingerprint_database *database,
                    struct os_match **matches,
                    size_t *match_count);

