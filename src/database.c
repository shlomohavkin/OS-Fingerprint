#include "database.h"

#define SKIP_WHITESPACE(ptr)                         \
    do {                                             \
        while (isspace((unsigned char)*(ptr))) {      \
            ++(ptr);                                 \
        }                                            \
    } while (0)



/**
 * Function to free the memory allocated for a fingerprint group.
 */
void free_fingerprint_group(struct fingerprint_group *group) {
    if (group == NULL) {
        return;
    }

    for (size_t i = 0; i < group->field_count; i++) {
        free(group->fields[i].name);
        free(group->fields[i].value);
    }

    free(group->fields);
    free(group->name);

    *group = (struct fingerprint_group){0};
}

/**
 * Function to free the memory allocated for a match fingerprint.
 */
void free_match_fingerprint(struct match_fingerprint *fingerprint) {
    if (fingerprint == NULL) {
        return;
    }

    for (size_t i = 0; i < fingerprint->group_count; i++) {
        free_fingerprint_group(&fingerprint->groups[i]);
    }

    free(fingerprint->groups);

    *fingerprint = (struct match_fingerprint){0};
}

/**
 * Function to free the memory allocated for a database entry.
 */
void free_database_entry(struct database_entry *entry) {
    if (entry == NULL) {
        return;
    }

    free(entry->os_name);
    free_match_fingerprint(&entry->fingerprint);

    *entry = (struct database_entry){0};
}

/**
 * Function to free the memory allocated for match weights.
 */
void free_match_weights(struct match_weights *weights) {
    if (weights == NULL) {
        return;
    }
    for (size_t i = 0; i < weights->weight_count; i++) {
        free(weights->weights[i].group_name);
        free(weights->weights[i].field_name);
    }

    free(weights->weights);

    *weights = (struct match_weights){0};
}



/**
 * Function to parse a fingerprint group from a line of text, 
 * and populate the provided fingerprint_group structure.
 * @return 0 on success, -1 on error.
 */
int parse_fingerprint_group(const char *line, struct fingerprint_group *out) {
    if (line == NULL || out == NULL) {
        return -1;
    }

    struct fingerprint_group group = {0};

    SKIP_WHITESPACE(line);

    const char *open = strchr(line, '(');
    if (open == NULL) {
        return -1;
    }

    // Trim whitespace after the group name
    const char *name_end = open;
    while (name_end > line && isspace((unsigned char)name_end[-1])) {
        name_end--;
    }

    size_t group_name_len = (size_t)(name_end - line);
    if (group_name_len == 0) {
        return -1;
    }

    group.name = malloc(group_name_len + 1);
    if (group.name == NULL) {
        return -1;
    }

    memcpy(group.name, line, group_name_len);
    group.name[group_name_len] = '\0';

    line = open + 1;
    SKIP_WHITESPACE(line);

    // This parser requires at least one field
    if (*line == ')' || *line == '\0') {
        free_fingerprint_group(&group);
        return -1;
    }

    for (;;) {
        // Parse the field name
        const char *name_start = line;

        while (*line != '=' && *line != '%' &&
               *line != ')' && *line != '\0') {
            line++;
        }

        if (*line != '=') {
            free_fingerprint_group(&group);
            return -1;
        }

        name_end = line;
        while (name_end > name_start && isspace((unsigned char)name_end[-1])) {
            name_end--;
        }

        size_t name_len = (size_t)(name_end - name_start);
        if (name_len == 0) {
            free_fingerprint_group(&group);
            return -1;
        }

        // Parse the field value. Empty values are valid
        line++; // Skip '='
        SKIP_WHITESPACE(line);

        const char *value_start = line;

        while (*line != '%' && *line != ')' && *line != '\0') {
            line++;
        }

        if (*line == '\0') {
            free_fingerprint_group(&group);
            return -1;        
        }

        const char *value_end = line;
        while (value_end > value_start && isspace((unsigned char)value_end[-1])) {
            value_end--;
        }
        size_t value_len = (size_t)(value_end - value_start);

        // Grow the field array
        struct fingerprint_field *new_fields = realloc(group.fields, (group.field_count + 1) * sizeof(*group.fields));
        if (new_fields == NULL) {
            free_fingerprint_group(&group);
            return -1;
        }

        group.fields = new_fields;

        struct fingerprint_field *field = &group.fields[group.field_count];

        *field = (struct fingerprint_field){0};

        // Include this field in cleanup even if allocation fails.
        group.field_count++;

        field->name = malloc(name_len + 1);
        field->value = malloc(value_len + 1);

        if (field->name == NULL || field->value == NULL) {
            free_fingerprint_group(&group);
            return -1;
        }

        memcpy(field->name, name_start, name_len);
        field->name[name_len] = '\0';

        memcpy(field->value, value_start, value_len);
        field->value[value_len] = '\0';

        if (*line == ')') {
            line++; // Skip ')'
            break;
        }

        line++; // Skip '%'
        SKIP_WHITESPACE(line);

        if (*line == ')' || *line == '\0') {
            free_fingerprint_group(&group);
            return -1; // Missing field after '%'.
        }
    }

    // Only whitespace may follow the closing ')'.
    SKIP_WHITESPACE(line);

    if (*line != '\0') {
        free_fingerprint_group(&group);
        return -1;
    }

    *out = group;
    return 0;
}

/**
 * Function to parse an observed fingerprint from a string, 
 * and populate the provided match_fingerprint structure.
 * @return 0 on success, -1 on error.
 */
int parse_observed_fingerprint(const char *text, struct match_fingerprint *out) {
    if (text == NULL || out == NULL) {
        return -1;
    }

    struct match_fingerprint fingerprint = {0};
    const char *line = text;

    while (*line != '\0') {
        SKIP_WHITESPACE(line);
        if (*line == '\0') {
            break;
        }

        // save one line
        const char *next_line = strchr(line, '\n');
        size_t line_len = next_line != NULL ? (size_t)(next_line - line) : strlen(line);

        char *line_copy = malloc(line_len + 1);
        if (line_copy == NULL) {
            free_match_fingerprint(&fingerprint);
            return -1;
        }

        memcpy(line_copy, line, line_len);
        line_copy[line_len] = '\0';

        struct fingerprint_group group = {0};
        int result = parse_fingerprint_group(line_copy, &group);

        // free unused line copy after parsing, because the group parser 
        // creates its own copies of the name and fields.
        free(line_copy);

        if (result != 0) {
            free_match_fingerprint(&fingerprint);
            return -1;
        }

        // Grow the group array.
        struct fingerprint_group *new_groups = realloc(fingerprint.groups, (fingerprint.group_count + 1) * sizeof(*fingerprint.groups));
        if (new_groups == NULL) {
            free_fingerprint_group(&group);
            free_match_fingerprint(&fingerprint);
            return -1;
        }

        fingerprint.groups = new_groups;
        fingerprint.groups[fingerprint.group_count++] = group;

        if (next_line == NULL) {
            break;
        }

        line = next_line + 1; // Skip the newline character
    }

    *out = fingerprint;
    return 0;
}

/**
 * Adds the weights from a fingerprint group to the match_weights structure.
 * @return 0 on success, -1 on error.
 */
static int add_group_weights(const struct fingerprint_group *group, struct match_weights *out) {
    for (size_t i = 0; i < group->field_count; i++) {
        const struct fingerprint_field *field = &group->fields[i];
        const char *value = field->value;

        // Accept decimal digits only.
        if (*value == '\0') {
            return -1;
        }

        for (const char *p = value; *p != '\0'; p++) {
            if (!isdigit((unsigned char)*p)) {
                return -1;
            }
        }

        errno = 0;
        char *end;
        unsigned long points = strtoul(value, &end, 10);

        if (errno == ERANGE || *end != '\0' || points > UINT_MAX) {
            return -1;
        }

        // Reject duplicate weights
        for (size_t j = 0; j < out->weight_count; j++) {
            if (strcmp(out->weights[j].group_name, group->name) == 0 &&
                strcmp(out->weights[j].field_name, field->name) == 0) {
                return -1;
            }
        }

        struct match_weight weight = {
            .group_name = strdup(group->name),
            .field_name = strdup(field->name),
            .points = (unsigned int)points
        };
        if (weight.group_name == NULL || weight.field_name == NULL) {
            free(weight.group_name);
            free(weight.field_name);
            return -1;
        }

        struct match_weight *new_weights = realloc(out->weights, (out->weight_count + 1) * sizeof(*out->weights));
        if (new_weights == NULL) {
            free(weight.group_name);
            free(weight.field_name);
            return -1;
        }

        out->weights = new_weights;
        out->weights[out->weight_count++] = weight;
    }

    return 0;
}

/**
 * Reads the MatchPoints section from the database file and populates the match_weights structure.
 * This function is one of the two function that are used in the matcher.c file to read the databse file
 * and extract the match weights for each group and field. The other function is read_next_reference.
 * @param file The database file to read from.
 * @param out The match_weights structure to populate.
 * @return 0 on success, -1 on error.
 */
int read_match_weights(FILE *file, struct match_weights *out) {
    if (file == NULL || out == NULL) {
        return -1;
    }

    struct match_weights weights = {0};
    char *line = NULL;
    size_t line_capacity = 0;
    bool found = false;

    for (;;) {
        if (getline(&line, &line_capacity, file) == -1) {
            if (ferror(file) || !feof(file)) {
                fprintf(stderr, "Error reading database file\n");
                free(line);
                free_match_weights(&weights);
                return -1;
            }

            break; // Normal EOF.
        }

        char *p = line;
        SKIP_WHITESPACE(p);

        // Remove trailing whitespace, including newline.
        size_t len = strlen(p);
        while (len > 0 && isspace((unsigned char)p[len - 1])) {
            p[--len] = '\0';
        }

        if (*p == '\0' || *p == '#') {
            continue;
        }

        if (!found) {
            if (strcmp(p, "MatchPoints") == 0) {
                found = true;
            }
            continue;
        }

        if (strncmp(p, "Fingerprint", 11) == 0 &&
            isspace((unsigned char)p[11])) {
            break;
        }

        struct fingerprint_group group = {0};

        if (parse_fingerprint_group(p, &group) < 0) {
            fprintf(stderr, "Failed to parse MatchPoints group: %s\n", p);
            free(line);
            free_match_weights(&weights);
            return -1;
        }

        int status = add_group_weights(&group, &weights);
        free_fingerprint_group(&group);

        if (status < 0) {
            fprintf(stderr, "Failed to add group weights for group: %s\n", group.name);
            free(line);
            free_match_weights(&weights);
            return -1;
        }
    }

    if (ferror(file) || !found || weights.weight_count == 0) {
        fprintf(stderr, "Failed to read MatchPoints section from database file\n");
        free(line);
        free_match_weights(&weights);
        return -1;
    }

    free(line);
    *out = weights;
    return 0;
}


/**
 * Reads the next reference fingerprint from the database file and populates the database_entry structure.
 * This is the second function that is used in the matcher.c file to read the databse file and 
 * extract the reference fingerprints for each OS.
 * @param file The database file to read from.
 * @param out The database_entry structure to populate.
 * @return 1 if an entry was read, 0 if EOF was reached, -1 on error.
 */
int read_next_reference(FILE *file, struct database_entry *out) {
    if (file == NULL || out == NULL) {
        return -1;
    }

    struct database_entry entry = {0};
    char *line = NULL;
    size_t line_capacity = 0;
    bool found = false;

    for (;;) {
        // Remember where this line starts
        fpos_t position;
        if (fgetpos(file, &position) != 0) {
            fprintf(stderr, "Failed to get file position\n");
            free(line);
            free_database_entry(&entry);
            return -1;
        }

        if (getline(&line, &line_capacity, file) == -1) {
            // getline() can also fail for reasons other than EOF.
            if (ferror(file) || !feof(file)) {
                fprintf(stderr, "Error reading database file\n");
                free(line);
                free_database_entry(&entry);
                return -1;
            }
            break;
        }

        char *p = line;
        SKIP_WHITESPACE(p);

        // Remove trailing whitespace, including the newline.
        size_t len = strlen(p);
        while (len > 0 && isspace((unsigned char)p[len - 1])) {
            p[--len] = '\0';
        }

        if (*p == '\0' || *p == '#') {
            continue;
        }

        bool is_header = strncmp(p, "Fingerprint", 11) == 0 &&
                        (p[11] == '\0' || isspace((unsigned char)p[11]));

        if (is_header) {
            if (found) {
                // Leave the next entry's header for the next call
                if (fsetpos(file, &position) != 0) {
                    fprintf(stderr, "Failed to set file position\n");
                    free(line);
                    free_database_entry(&entry);
                    return -1;
                }
                break;
            }

            p += 11; // Skip "Fingerprint"
            SKIP_WHITESPACE(p);

            if (*p == '\0') {
                fprintf(stderr, "Fingerprint header missing OS name\n");
                free(line);
                free_database_entry(&entry);
                return -1;
            }

            entry.os_name = strdup(p);
            if (entry.os_name == NULL) {
                fprintf(stderr, "Failed to allocate memory for OS name\n");
                free(line);
                free_database_entry(&entry);
                return -1;
            }

            found = true;
            continue;
        }

        // Skip MatchPoints and other content before the first entry
        if (!found) {
            continue;
        }

        // Metadata is not used by this matcher yet.
        if ((strncmp(p, "Class", 5) == 0 && (p[5] == '\0' || isspace((unsigned char)p[5]))) ||
            (strncmp(p, "CPE", 3) == 0 && (p[3] == '\0' || isspace((unsigned char)p[3])))) {
            continue;
        }

        struct fingerprint_group group = {0};

        if (parse_fingerprint_group(p, &group) != 0) {
            fprintf(stderr, "Failed to parse fingerprint group: %s\n", p);
            free(line);
            free_database_entry(&entry);
            return -1;
        }

        struct match_fingerprint *fingerprint = &entry.fingerprint;

        // A fingerprint should not have duplicate group names 
        for (size_t i = 0; i < fingerprint->group_count; i++) {
            if (strcmp(fingerprint->groups[i].name, group.name) == 0) {
                fprintf(stderr, "Duplicate group name in fingerprint: %s\n", group.name);
                free_fingerprint_group(&group);
                free(line);
                free_database_entry(&entry);
                return -1;
            }
        }

        if (fingerprint->group_count >= SIZE_MAX / sizeof(*fingerprint->groups)) {
            fprintf(stderr, "Too many groups in fingerprint\n");
            free_fingerprint_group(&group);
            free(line);
            free_database_entry(&entry);
            return -1;
        }

        struct fingerprint_group *new_groups = realloc(fingerprint->groups, (fingerprint->group_count + 1) * sizeof(*fingerprint->groups));
        if (new_groups == NULL) {
            fprintf(stderr, "Failed to allocate memory for fingerprint groups\n");
            free_fingerprint_group(&group);
            free(line);
            free_database_entry(&entry);
            return -1;
        }

        fingerprint->groups = new_groups;
        fingerprint->groups[fingerprint->group_count++] = group;
    }

    free(line);

    if (!found) {
        return 0; // EOF with no more entries.
    }

    if (entry.fingerprint.group_count == 0) {
        fprintf(stderr, "Fingerprint for OS '%s' has no groups\n", entry.os_name);
        free_database_entry(&entry);
        return -1;
    }

    *out = entry; // Transfer ownership to the caller.
    return 1;
}
