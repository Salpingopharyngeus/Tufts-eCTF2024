/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "board.h"
#include "dma.h"
#include "aes.h"
#include "aes_regs.h"


#define MXC_AES_DATA_LENGTH 8
volatile int dma_flag = 0;

void DMA0_IRQHandler() {
    MXC_DMA_Handler();
    dma_flag++;
}


/**
 * FUNCTION CONTRACT TO DO
 *
 *
 * Can only encrypt using external key
 */
// Easiest way would be to pass in a parameter of type mxc_aes_req_t, the MXC_AES functions utilize that
int AES_encrypt(int asynchronous, mxc_aes_keys_t key, uint32_t* inputData, uint32_t* encryptedData) {
    int err = E_NO_ERROR;
    err = MXC_AES_Init();
    if (err) return err; // TODO: check if this is secure against some kind of attack?

    // Declare data for an AES request
    mxc_aes_req_t req;
    req.length = MXC_AES_DATA_LENGTH;
    req.inputData = inputData;
    req.resultData = encryptedData;
    req.keySize = key;
    req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

    // TODO: check if asynchronous compatability works, and if we need it.
    if (asynchronous) {
        MXC_AES_EncryptAsync(&req);
        if (err) return err;

        // Blocking Loop?
        while (dma_flag == 0);
        dma_flag = 0;
    }
    else {
        // Non-asynchronous encrypt function
        err = MXC_AES_Encrypt(&req);
        if (err) return err;
    }
    
    MXC_AES_Shutdown();

    return err;
}

int AES_decrypt(int asynchronous, mxc_aes_keys_t key, mxc_aes_enc_type_t key_method, uint32_t* inputData, uint32_t* decryptedData) {
    int err = E_NO_ERROR;
    err = MXC_AES_Init();
    if (err) return err; // TODO: check if this is secure against some kind of attack?

    // Declare data for an AES request
    mxc_aes_req_t req;
    req.length = MXC_AES_DATA_LENGTH;
    req.inputData = inputData;
    req.resultData = decryptedData;
    req.keySize = key;
    req.encryption = key_method; // From param, must tell if decryption is done via ext. or internal key.

    if (asynchronous) {
        err = MXC_AES_DecryptAsync(&req);
        if (err) return err;

        // Blocking Loop
        while (dma_flag == 0) {}

        dma_flag = 0;

    } else {
        err = MXC_AES_Decrypt(&req);
        if (err) return err;
    }

    MXC_AES_Shutdown();
    return err;
}