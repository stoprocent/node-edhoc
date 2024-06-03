#ifndef SUITES_H
#define SUITES_H

extern "C" {
#include "edhoc.h"
}

/**
 * @brief Array of pointers to EDHOC cipher suites.
 *
 * This array contains pointers to the available EDHOC cipher suites.
 * Each cipher suite is represented by a struct of type `edhoc_cipher_suite`.
 * The array is declared as `extern` to allow access from other source files.
 *
 * @see edhoc_cipher_suite
 */
extern const struct edhoc_cipher_suite* suite_pointers[];

/**
 * @brief Number of EDHOC cipher suites.
 *
 * This variable holds the number of available EDHOC cipher suites.
 * It is declared as `extern` to allow access from other source files.
 */
extern const size_t suite_pointers_count;

#endif  // SUITES_H
