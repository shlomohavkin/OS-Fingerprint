#include "matcher.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

// Not declared in matcher.h. Remove this line if you add it there.
int match_expression(const char *observed, const char *expression, bool tcp_options);

#define MATCH     1
#define NO_MATCH  0
#define INVALID  -1

static void test_null_and_empty(void) {
    assert(match_expression(NULL, "A", false) == INVALID);
    assert(match_expression("A", NULL, false) == INVALID);
    assert(match_expression("", "", false) == MATCH);
    assert(match_expression("A", "", false) == NO_MATCH);
}

static void test_literals(void) {
    assert(match_expression("0A", "a", false) == MATCH);   // compared by hex value
    assert(match_expression("5", "6", false) == NO_MATCH);

    assert(match_expression("A+", "A+", false) == MATCH);  // non-numeric, compared as text
    assert(match_expression("Y", "N", false) == NO_MATCH);
}

static void test_operators(void) {
    assert(match_expression("A", ">9", false) == MATCH);
    assert(match_expression("3", "<3", false) == NO_MATCH);

    assert(match_expression("A", "1-A", false) == MATCH);
    assert(match_expression("B", "1-A", false) == NO_MATCH);

    assert(match_expression("5", "A-1", false) == INVALID);  // lower > upper
    assert(match_expression("5", "~5", false) == INVALID);   // unsupported operator
}

static void test_or(void) {
    assert(match_expression("N", "Y|N", false) == MATCH);
    assert(match_expression("X", "Y|N", false) == NO_MATCH);
    assert(match_expression("1", "1|~", false) == INVALID);  
}

static void test_tcp_options(void) {
    assert(match_expression("M5B4NW5T11S", "M5B4NW5T11S", true) == MATCH);
    assert(match_expression("FF", "ff", true) == NO_MATCH);  // case sensitive for options
    assert(match_expression("M5B4ST", "M[400-5B4]ST", true) == MATCH);
    assert(match_expression("M5B5ST", "M[400-5B4]ST", true) == NO_MATCH);
}

static void test_invalid_brackets(void) {
    assert(match_expression("5", "[5]", false) == INVALID);  // brackets only allowed for tcp options
    assert(match_expression("M5", "M[5", true) == INVALID);
    assert(match_expression("M5", "M[]", true) == INVALID);  // empty brackets
}

int main(void) {
    test_null_and_empty();
    test_literals();
    test_operators();
    test_or();
    test_tcp_options();
    test_invalid_brackets();

    printf("All expression matcher tests passed successfully.\n\n");
    return 0;
}