#ifndef DATABASE_H
#define DATABASE_H

#include "fingerprint.h"
#include <ctype.h>


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

struct fingerprint_database {
    struct database_entry *entries;
    size_t entry_count;

    struct match_weight *weights;
    size_t weight_count;
};

struct os_match {
    size_t entry_index;       // Index in database.entries.
    size_t compared_fields;
    uint64_t matched_points;
    uint64_t possible_points;
    double score;            // Between 0.0 and 1.0.
};

#endif /* DATABASE_H */