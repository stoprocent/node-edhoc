#ifndef SUITES_H
#define SUITES_H

extern "C" {
    #include "edhoc.h"
}

extern const struct edhoc_cipher_suite* suite_pointers[];
extern const size_t suite_pointers_count;

#endif // SUITES_H
