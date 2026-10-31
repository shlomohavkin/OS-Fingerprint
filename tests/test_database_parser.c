#include "database.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define SUCCESS          0
#define FAILURE         -1
#define ENTRY_READ       1   // read_next_reference: an entry was read
#define NO_MORE_ENTRIES  0   // read_next_reference: end of file

// Creates a temporary file containing the given text, ready to be read.
static FILE *open_text(const char *text) {
    FILE *file = tmpfile();
    assert(file != NULL);
    fputs(text, file);
    rewind(file);
    return file;
}

static void test_parse_observed_fingerprint(void) {
    struct match_fingerprint fingerprint = {0};

    // Valid: two groups with a blank line between them, and an empty field value
    assert(parse_observed_fingerprint("SEQ(SP=A5%GCD=1)\n\nT1(R=Y%Q=)\n", &fingerprint) == SUCCESS);
    assert(fingerprint.group_count == 2);
    assert(strcmp(fingerprint.groups[0].name, "SEQ") == 0);
    assert(fingerprint.groups[0].field_count == 2);
    assert(strcmp(fingerprint.groups[0].fields[1].name, "GCD") == 0);
    assert(strcmp(fingerprint.groups[0].fields[1].value, "1") == 0);
    assert(strcmp(fingerprint.groups[1].fields[1].value, "") == 0);
    free_match_fingerprint(&fingerprint);

    // Invalid
    assert(parse_observed_fingerprint("SEQ(SP=1", &fingerprint) == FAILURE);  // missing ')'
    assert(parse_observed_fingerprint("SEQ()", &fingerprint) == FAILURE);      // no fields
    assert(parse_observed_fingerprint(NULL, &fingerprint) == FAILURE);
}

static void test_read_match_weights(void) {
    struct match_weights weights = {0};

    // Valid: comments and blank lines are skipped, and reading stops at the first "Fingerprint" line
    FILE *file = open_text( "# comment\n"
                            "MatchPoints\n"
                            "SEQ(SP=25%GCD=75)\n"
                            "OPS(O1=20)\n\n"
                            "Fingerprint Linux\n"
                            "SEQ(SP=1)\n");
    assert(read_match_weights(file, &weights) == SUCCESS);
    assert(weights.weight_count == 3);
    assert(strcmp(weights.weights[0].group_name, "SEQ") == 0);
    assert(strcmp(weights.weights[0].field_name, "SP") == 0);
    assert(weights.weights[0].points == 25);
    assert(weights.weights[2].points == 20);
    free_match_weights(&weights);
    fclose(file);

    // Invalid: no MatchPoints section
    file = open_text("SEQ(SP=25)\n");
    assert(read_match_weights(file, &weights) == FAILURE);
    fclose(file);

    // Invalid: a weight that is not a number
    file = open_text("MatchPoints\nSEQ(SP=abc)\n");
    assert(read_match_weights(file, &weights) == FAILURE);
    fclose(file);
}

static void test_read_next_reference(void) {
    struct database_entry entry = {0};

    // Valid: lines before the first entry and the Class/CPE lines are ignored
    FILE *file = open_text( "MatchPoints\n"
                            "SEQ(SP=25)\n\n"
                            "Fingerprint Linux 5.x\n"
                            "Class Linux | Linux | 5.X | general purpose\n"
                            "CPE cpe:/o:linux:linux_kernel:5\n"
                            "SEQ(SP=A5-B5%GCD=1)\n"
                            "OPS(O1=M5B4)\n\n"
                            "Fingerprint Windows 10\n"
                            "SEQ(SP=1)\n");

    assert(read_next_reference(file, &entry) == ENTRY_READ);
    assert(strcmp(entry.os_name, "Linux 5.x") == 0);
    assert(entry.fingerprint.group_count == 2);
    free_database_entry(&entry);

    assert(read_next_reference(file, &entry) == ENTRY_READ);
    assert(strcmp(entry.os_name, "Windows 10") == 0);
    assert(entry.fingerprint.group_count == 1);
    free_database_entry(&entry);

    assert(read_next_reference(file, &entry) == NO_MORE_ENTRIES);
    fclose(file);

    // Invalid: duplicate group in one fingerprint
    file = open_text(   "Fingerprint A\n"
                        "SEQ(SP=1)\n"
                        "SEQ(SP=2)\n");
    assert(read_next_reference(file, &entry) == FAILURE);
    fclose(file);

    // Invalid: fingerprint without any groups
    file = open_text("Fingerprint A\n");
    assert(read_next_reference(file, &entry) == FAILURE);
    fclose(file);
}

int main(void) {
    test_parse_observed_fingerprint();
    test_read_match_weights();
    test_read_next_reference();

    printf("All database parser tests passed successfully.\n");
    return 0;
}