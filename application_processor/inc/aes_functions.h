#ifndef AES_FUNCTIONS_H
#define AES_FUNCTIONS_H

#include <stdint.h>
#include "aes.h"

int AES_encrypt(int asynchronous, mxc_aes_keys_t key, uint32_t* inputData, uint32_t* encryptedData);

int AES_decrypt(int asynchronous, mxc_aes_keys_t key, mxc_aes_enc_type_t key_method, uint32_t* inputData, uint32_t* decryptedData);

#endif /* AES_FUNCTIONS_H */
