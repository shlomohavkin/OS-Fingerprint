#ifndef MATCHER_H
#define MATCHER_H

#include "fingerprint.h"
#include "database.h"

/**
 * The main function that is called to find the best OS matches based on 
 * the observed fingerprint and the reference database. This function reads the database, 
 * compares the fingerprints, and retains the best matches.
 * @param database_path The path to the database file containing known fingerprints.
 * @param observed_fingerprint_string The string representation of the observed fingerprint.
 * @param best_matches An array to store the best matches found.
 * @param max_matches The maximum number of matches to retain in the best_matches array.
 * @param match_count A pointer to store the number of matches found.
 * @return 0 on success, -1 on error.
 */
int find_os_matches(const char *database_path, const char *observed_fingerprint_string, struct os_match *best_matches, const size_t max_matches, size_t *match_count);

/**
 * Function to free the memory allocated for the best_matches array.
 * @param matches The array of os_match structures to free.
 * @param match_count The number of matches in the array.
 */
void free_os_matches(struct os_match *matches, size_t match_count);


/**
 * The is the main function that calls the recursive match_expression_slice function.
 * The function checks if the observed string matches the expression string based on 
 * the defined matching rules.
 * @return 1 for match, 0 for mismatch, -1 for invalid/unsupported expression.
 */
int match_expression(const char *observed, const char *expression, bool tcp_options);

#endif /* MATCHER_H */