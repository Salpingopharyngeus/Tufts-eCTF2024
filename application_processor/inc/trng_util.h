// trng_util.h
#ifndef TRNG_UTIL_H
#define TRNG_UTIL_H

#include <stdint.h>

void TRNG_Init(void);
void TRNG_GenerateRandomID(uint8_t* id, int idSize);
void TRNG_Shutdown(void);

#endif // TRNG_UTIL_H
