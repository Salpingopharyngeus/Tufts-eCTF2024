// trng_util.c
#include "trng_util.h"
#include "mxc_device.h"
#include "trng.h"
#include <string.h>

void TRNG_Init(void) {
    MXC_TRNG_Init();
}

uint32_t TRNG_GenerateRandomID(void) {
    uint32_t id;
    MXC_TRNG_Random((uint8_t*)&id, sizeof(id));
    return id;
}

void TRNG_Shutdown(void) {
    MXC_TRNG_Shutdown();
}
