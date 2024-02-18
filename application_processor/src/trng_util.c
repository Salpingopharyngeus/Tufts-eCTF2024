// trng_util.c
#include "trng_util.h"
#include "mxc_device.h"
#include "trng.h"
#include <string.h>

void TRNG_Init(void) {
    MXC_TRNG_Init();
}

void TRNG_GenerateRandomID(uint8_t* id, int idSize) {
    MXC_TRNG_Random(id, idSize);
}

void TRNG_Shutdown(void) {
    MXC_TRNG_Shutdown();
}
