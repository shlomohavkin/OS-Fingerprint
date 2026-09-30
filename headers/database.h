#ifndef DATABASE_H
#define DATABASE_H

#include "fingerprint.h"
#include <ctype.h>
#include <stdio.h>


struct fingerprint_field {
    char *name;
    char *value;
};

struct fingerprint_group {
    char *name;
    struct fingerprint_field *fields;
    size_t field_count;
};

struct match_fingerprint {
    struct fingerprint_group *groups;
    size_t group_count;
};

struct database_entry {
    char *os_name;
    struct match_fingerprint fingerprint;
};

struct match_weight {
    char *group_name;
    char *field_name;
    unsigned int points;
};

struct match_weights {
    struct match_weight *weights;
    size_t weight_count;
};

struct os_match {
    char *os_name;
    size_t compared_fields;
    uint64_t matched_points;
    uint64_t possible_points;
    double score;            // Between 0.0 and 1.0.
};


int read_match_weights(FILE *file, struct match_weights *out);
int read_next_reference(FILE *file, struct database_entry *out);
int parse_observed_fingerprint(const char *text, struct match_fingerprint *out);

void free_match_fingerprint(struct match_fingerprint *fingerprint);
void free_database_entry(struct database_entry *entry);
void free_match_weights(struct match_weights *weights);

#endif /* DATABASE_H */