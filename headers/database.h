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
    double score;            // Between 0.0 and 1.0
};


/**
 * Reads the MatchPoints section from the database file and populates the match_weights structure.
 * This function is one of the two function that are used in the matcher.c file to read the databse file
 * and extract the match weights for each group and field. The other function is read_next_reference.
 * @param file The database file to read from.
 * @param out The match_weights structure to populate.
 * @return 0 on success, -1 on error.
 */
int read_match_weights(FILE *file, struct match_weights *out);

/**
 * Reads the next reference fingerprint from the database file and populates the database_entry structure.
 * This is the second function that is used in the matcher.c file to read the databse file and 
 * extract the reference fingerprints for each OS.
 * @param file The database file to read from.
 * @param out The database_entry structure to populate.
 * @return 1 if an entry was read, 0 if EOF was reached, -1 on error.
 */
int read_next_reference(FILE *file, struct database_entry *out);

/**
 * Function to parse an observed fingerprint from a string, 
 * and populate the provided match_fingerprint structure.
 * @param text The string representation of the observed fingerprint.
 * @param out The match_fingerprint structure to populate.
 * @return 0 on success, -1 on error.
 */
int parse_observed_fingerprint(const char *text, struct match_fingerprint *out);


/**
 * Function to free the memory allocated for a match fingerprint.
 */
void free_match_fingerprint(struct match_fingerprint *fingerprint);

/**
 * Function to free the memory allocated for a database entry.
 */
void free_database_entry(struct database_entry *entry);

/**
 * Function to free the memory allocated for match weights.
 */
void free_match_weights(struct match_weights *weights);

#endif /* DATABASE_H */