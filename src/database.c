#include "database.h"

#define SKIP_WHITESPACE(ptr)                         \
    do {                                             \
        while (isspace((unsigned char)*(ptr))) {      \
            ++(ptr);                                 \
        }                                            \
    } while (0)

    
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


/* This function:
1. Opens the file.
2. Reads lines using getline().
3. Recognizes MatchPoints and Fingerprint ....
4. Parses group lines.
5. Adds completed entries to the database.
6. Handles the final entry at EOF.
Initially, skip Class and CPE metadata.*/
int load_fingerprint_database(const char *path, struct fingerprint_database *out);

int parse_match_points_group(const char *line, struct fingerprint_database *database);


void free_fingerprint_group(struct fingerprint_group *group);

void free_match_fingerprint(struct match_fingerprint *fingerprint);

void free_fingerprint_database(struct fingerprint_database *database);
