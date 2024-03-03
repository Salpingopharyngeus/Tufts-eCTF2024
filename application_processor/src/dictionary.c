// dictionary.c
#include "dictionary.h"
#include <stdio.h>

void initDictionary(Dictionary* dict) {
    // Check if the dictionary has already been initialized
    if (dict->pairs != NULL || dict->size != 0) {
        return;
    }
    dict->pairs = NULL;
    dict->size = 0;
}

void addOrUpdate(Dictionary* dict, uint8_t key, uint32_t value) {
    for (size_t i = 0; i < dict->size; i++) {
        if (dict->pairs[i].key == key) {
            dict->pairs[i].value = value;
            return;
        }
    }
    KeyValue* newPairs = realloc(dict->pairs, (dict->size + 1) * sizeof(KeyValue));
    if (newPairs == NULL) {
        // Handle allocation error
        return;
    }
    dict->pairs = newPairs;
    dict->pairs[dict->size].key = key;
    dict->pairs[dict->size].value = value;
    dict->size += 1;
}

uint32_t getValue(Dictionary* dict, uint8_t key) {
    for (size_t i = 0; i < dict->size; i++) {
        if (dict->pairs[i].key == key) {
            return dict->pairs[i].value;
        }
    }
    return 0xFFFFFFFF; // Key not found
}

void freeDictionary(Dictionary* dict) {
    free(dict->pairs);
    dict->pairs = NULL;
    dict->size = 0;
}