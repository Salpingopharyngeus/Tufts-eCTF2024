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

/**
 * @brief initDictionary
 * 
 * @param dict: Dictionary*, pointer to Dictionary struct obj
 * 
 * Initialize a new Dictionary struct object with empty key value pairs.
*/
void initDictionary(Dictionary* dict);

/**
 * @brief addOrUpdate
 * 
 * @param dict: Dictionary*, pointer to Dictionary struct obj
 * @param key: uint8_t, represents the given component ID
 * @param value: uint32_t, represents the given random_number
 * 
 * Add or update new key value pair to given dict
*/
void addOrUpdate(Dictionary* dict, uint8_t key, uint32_t value);

/**
 * @brief getValue
 * 
 * @param dict: Dictionary*, pointer to Dictionary struct obj
 * @param key: uint8_t, represents the given component ID
 * @return uint32_t: return random_number assigned to given key
 * 
 * return value of associated key
*/
uint32_t getValue(Dictionary* dict, uint8_t key);

/**
 * @brief freeDictionary
 * 
 * @param dict: Dictionary*, pointer to Dictionary struct obj
 * 
 * Free dict memory
*/
void freeDictionary(Dictionary* dict);

#endif // DICTIONARY_H