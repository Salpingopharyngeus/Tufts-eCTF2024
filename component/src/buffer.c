#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint32_t* data;
    size_t capacity;
    size_t size;
} Uint32Buffer;

Uint32Buffer* createUint32Buffer(size_t initialCapacity) {
    Uint32Buffer* buffer = (Uint32Buffer*)malloc(sizeof(Uint32Buffer));
    if (buffer) {
        buffer->data = (uint32_t*)malloc(initialCapacity * sizeof(uint32_t));
        if (buffer->data) {
            buffer->capacity = initialCapacity;
            buffer->size = 0;
        } else {
            free(buffer);
            buffer = NULL;
        }
    }
    return buffer;
}

void destroyUint32Buffer(Uint32Buffer* buffer) {
    if (buffer) {
        free(buffer->data);
        free(buffer);
    }
}

int appendToUint32Buffer(Uint32Buffer* buffer, uint32_t value) {
    if (buffer->size >= buffer->capacity) {
        size_t newCapacity = buffer->capacity * 2;
        uint32_t* newData = (uint32_t*)realloc(buffer->data, newCapacity * sizeof(uint32_t));
        if (!newData) {
            // Memory reallocation failed
            return -1;
        }
        buffer->data = newData;
        buffer->capacity = newCapacity;
    }
    buffer->data[buffer->size++] = value;
    return 0;
}

int searchUint32Buffer(const Uint32Buffer* buffer, uint32_t value) {
    for (size_t i = 0; i < buffer->size; ++i) {
        if (buffer->data[i] == value) {
            return 1; // Found
        }
    }
    return 0; // Not found
}
