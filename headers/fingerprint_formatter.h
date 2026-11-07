#ifndef FINGERPRINT_FORMATTER_H
#define FINGERPRINT_FORMATTER_H

#include "fingerprint.h"

/**
 * Main function to format the OS fingerprint into a string representation.
 * @param fingerprint The OS fingerprint to format.
 * @param buffer The buffer where the formatted string will be stored.
 * @return The number of characters written to the buffer (excluding the null terminator) 
 * if successful, or -1 on error (e.g., if the buffer is too small to hold the 
 */
int format_os_fingerprint(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity);

#endif 