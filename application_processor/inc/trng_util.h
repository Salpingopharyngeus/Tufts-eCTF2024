// trng_util.h
#ifndef TRNG_UTIL_H
#define TRNG_UTIL_H

#include <stdint.h>

void TRNG_Init(void);
uint32_t TRNG_GenerateRandomID(void);
void TRNG_Shutdown(void);

#endif // TRNG_UTIL_H
