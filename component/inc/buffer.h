#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>

typedef struct {
    uint32_t* data;
    size_t capacity;
    size_t size;
} Uint32Buffer;

Uint32Buffer* createUint32Buffer(size_t initialCapacity);
void destroyUint32Buffer(Uint32Buffer* buffer);
int appendToUint32Buffer(Uint32Buffer* buffer, uint32_t value);
int searchUint32Buffer(const Uint32Buffer* buffer, uint32_t value);

#endif /* BUFFER_H */