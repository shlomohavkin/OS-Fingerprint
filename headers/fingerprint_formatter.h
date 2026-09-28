#ifndef FINGERPRINT_FORMATTER_H
#define FINGERPRINT_FORMATTER_H

#include "fingerprint.h"


int format_os_fingerprint(const struct os_fingerprint *fingerprint, char *buffer, size_t capacity);

#endif 