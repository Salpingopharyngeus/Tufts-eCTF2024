// dictionary.h
#ifndef DICTIONARY_H
#define DICTIONARY_H

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t key;
    uint32_t value;
} KeyValue;

typedef struct {
    KeyValue* pairs;
    size_t size;
} Dictionary;

void initDictionary(Dictionary* dict);
void addOrUpdate(Dictionary* dict, uint8_t key, uint32_t value);
uint32_t getValue(Dictionary* dict, uint8_t key);
void freeDictionary(Dictionary* dict);

#endif // DICTIONARY_H