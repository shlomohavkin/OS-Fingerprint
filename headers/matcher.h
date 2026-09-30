#ifndef MATCHER_H
#define MATCHER_H

#include "fingerprint.h"
#include "database.h"


int find_os_matches(const char *database_path, const char *observed_fingerprint_string, struct os_match *best_matches, const size_t max_matches, size_t *match_count);
void free_os_matches(struct os_match *matches, size_t match_count);

#endif /* MATCHER_H */