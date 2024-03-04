#define MXC_AES_DATA_LENGTH 8 //4 words
#define MAX_I2C_MESSAGE_LEN 256

#define ERROR_RETURN 1
#define SUCCESS_RETURN 0

#define COMPONENT_IDS {0x11111124, 0x11111125} // *** point of interest, from .h had no {} ***
#define COMPONENT_CNT 2
#include <stdint.h>
#include <stdio.h>
#include <string.h>

volatile int dma_flag = 0;

typedef enum {
    MXC_AES_128BITS, ///< Select AES-128 bit key
    MXC_AES_192BITS, ///< Select AES-192 bit key
    MXC_AES_256BITS, ///< Select AES-256 bit key
} mxc_aes_keys_t;

/**
  * @brief  Enumeration type to select AES key source and encryption type
  *
  */
typedef enum {
    MXC_AES_ENCRYPT_EXT_KEY = 0, ///< Encryption using External key
    MXC_AES_DECRYPT_EXT_KEY = 1, ///< Encryption using internal key
    MXC_AES_DECRYPT_INT_KEY = 2 ///< Decryption using internal key
} mxc_aes_enc_type_t;

/**
  * @brief  Structure used to set up AES request
  *
  */
typedef struct _mxc_aes_cipher_req_t {
    uint32_t length; ///< Length of the data
    uint32_t *inputData; ///< Pointer to input data
    uint32_t *resultData; ///< Pointer to encrypted data
    mxc_aes_keys_t keySize; ///< Size of AES key
    mxc_aes_enc_type_t encryption; ///< Encrytion type or \ref mxc_aes_enc_type_t
    // mxc_aes_complete_t callback; ///< Callback function
} mxc_aes_req_t;

int MXC_AES_Encrypt(mxc_aes_req_t* req){
    uint32_t* inputpt = req->inputData;
    uint32_t* outputpt = req->resultData;
    *outputpt = *inputpt + 1;
    printf("\n\t*** MXC_AES_Encrypt Call ***\n");
    printf("Length: %d\n", req->length);
    printf("inputData: %d\n", *inputpt);
    printf("resultData: %d\n", *outputpt);
    printf("keySize: %d\n", req->keySize);
    printf("encryption: %d\n", req->encryption);
    printf("\t*** END MXC_AES_Encrypt END ***\n\n");
    return 0;
}

int MXC_AES_Decrypt(mxc_aes_req_t* req){
    uint32_t* inputpt = req->inputData;
    uint32_t* outputpt = req->resultData;
    *outputpt = *inputpt - 1;
    printf("\n\n\t*** MXC_AES_Decrypt Call ***\n");
    printf("Length: %d\n", req->length);
    printf("inputData: %d\n", *inputpt);
    printf("resultData: %d\n", *outputpt);
    printf("keySize: %d\n", req->keySize);
    printf("encryption: %d\n", req->encryption);
    printf("\t*** END MXC_AES_Decrypt END ***\n\n");
    return 0;
}

void print_array(uint8_t* arr) {
    printf("\n\nContents of arr: \n");
    for (int i = 0; i < sizeof(arr); i++) {
        if (i < sizeof(arr) - 1) printf("%i, ", arr[i]);
        else printf("%i\n", arr[i]);
    }
}

void print_32barray(uint32_t* arr) {
    printf("\n\nContents of arr: \n");
    for (int i = 0; i < sizeof(arr); i++) {
        if (i < sizeof(arr) - 1) printf("%i, ", arr[i]);
        else printf("%i\n", arr[i]);
    }
}


/**
 * FUNCTION CONTRACT TO DO
 *
 *
 * Can only encrypt using external key
 */
// Easiest way would be to pass in a parameter of type mxc_aes_req_t, the MXC_AES functions utilize that
int AES_encrypt(int asynchronous, mxc_aes_keys_t key, uint32_t* inputData, uint32_t* encryptedData) {
    // int err = E_NO_ERROR;
    int err = 0;
    // err = MXC_AES_Init(); // DEBUG
    
    if (err) return err; // TODO: check if this is secure against some kind of attack?


    // Declare data for an AES request
    mxc_aes_req_t req;
    req.length = MXC_AES_DATA_LENGTH;
    req.inputData = inputData;
    req.resultData = encryptedData;
    req.keySize = key;
    req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

    printf("hi\n");
    printf("test data: %d\n", (*req.inputData));

    // TODO: check if asynchronous compatability works, and if we need it.
    if (asynchronous) {
        // MXC_AES_EncryptAsync(req); // DEBUG
        if (err) return err;

        // Blocking Loop?
        while (dma_flag == 0);
        dma_flag = 0;
    }
    else {
        // Non-asynchronous encrypt function
        err = MXC_AES_Encrypt(&req); // DEBUG
        if (err) return err;
    }
    
    // MXC_AES_Shutdown(); // DEBUG

    return err;
}

/**
 * @brief Send an arbitrary packet over I2C
 *        *** CHANGED GREATLY FOR EXAMPLE (NNITE) ***
 * 
 * @param address: i2c_addr_t, i2c address (NNITE)
 *                 *** Changed to int ***
 * @param len: uint8_t, length of the packet
 *                 *** BAD BAD BAD EVIL CHANGED THIS ***
 * @param packet: uint8_t*, pointer to packet to be sent
 * 
 * @return status: SUCCESS_RETURN if success, ERROR_RETURN if error
 *
 * Function sends an arbitrary packet over i2c to a specified component
*/
int send_packet(int address, int len, uint8_t* packet) {

    int result;
    // *** Approximate function of i2c_simple_write_data_generic ***
    // Creates a array of 257 8-bit elements
    uint8_t sending_packets[257]; // Was called packet (NNITE)
    // Sets the register to write to.
    sending_packets[0] = 42; // Was RECEIVE, but (NNITE)
    // Copies all data from "packet" in parameters to send, filling the remaining indices from 1 to 256.
    memcpy(&sending_packets[1], packet, len); // instead of "buf", use packet, (NNITE)

    printf("Size of packet (from send_packet parameters): %lu\n", sizeof(packet));

    printf("Value of len (from send_packet parameters): %i\n", len);

    // *** POTENTIAL FIX #1: do sizeof(packet), with additional math ***
    // *** NOT HERE, REQUIRES MORE THINKING, MAYBE UNSAFE ***

    // DEBUG ONLY
    // memcpy(&sending_packets[1], packet, 2); // instead of "buf", use packet, (NNITE)
    printf("Contents of sending_packets: \n");
    for (int i = 0; i < len; i++) {
        if (i < 257 - 1) printf("%i, ", sending_packets[i]);
        else printf("%i\n", sending_packets[i]);
    }

    return SUCCESS_RETURN;
}

/**
 * @brief Secure Send
 *
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be sent
 * @param len: uint8_t, size of data to be sent
 *
 * @return int: status of the sending process
 *
 * Securely send data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
int secure_send(uint8_t address, uint8_t *buffer, uint8_t len) {
    // Each segment is 32 bytes (256 bits)
    const uint8_t segmentSize = 32;
    
    // Calculate the total size needed for encrypted data (round up to nearest segment)
    uint8_t totalSegments = (len + segmentSize - 1) / segmentSize;
    uint8_t encryptedBuffer[totalSegments * segmentSize];
    memset(encryptedBuffer, 0, sizeof(encryptedBuffer));
    for (uint8_t i = 0; i < totalSegments; ++i) {
        uint32_t segment[segmentSize / 4]; // Temporary buffer for the current segment
        memset(segment, 0, sizeof(segment)); // Clear the segment buffer
        
        // Calculate the number of bytes to copy for this segment
        uint8_t bytesToCopy = len - (i * segmentSize);
        if (bytesToCopy > segmentSize) {
            bytesToCopy = segmentSize;
        }
        
        // Copy the current segment of the original buffer into the temporary buffer
        memcpy(segment, buffer + (i * segmentSize), bytesToCopy);

        // Encrypt the segment
        // Assuming AES_encrypt has been adjusted to accept uint8_t* and segment size
        // 2. Pass in this struct, pointer to the one you just created
        AES_encrypt(0, MXC_AES_256BITS, (uint32_t*)segment, (uint32_t*)encryptedBuffer);

        // memcpy(encryptedBuffer + (i * segmentSize), segment, segmentSize);
    }
    return send_packet(address, sizeof(encryptedBuffer), encryptedBuffer);
}

/**
 * TODO: Function CONTRACT
 * can decrypt using external or internal key
 */
int AES_decrypt(int asynchronous, mxc_aes_keys_t key, mxc_aes_enc_type_t key_method, uint32_t* inputData, uint32_t* decryptedData) {
    int err = 0;
    // err = MXC_AES_Init();
    if (err) return err; // TODO: check if this is secure against some kind of attack?

    // Declare data for an AES request
    mxc_aes_req_t req;
    req.length = MXC_AES_DATA_LENGTH;
    req.inputData = inputData;
    req.resultData = decryptedData;
    req.keySize = key;
    req.encryption = key_method; // From param, must tell if decryption is done via ext. or internal key.

    if (asynchronous) {
        // err = MXC_AES_DecryptAsync(&req);
        if (err) return err;

        // Blocking Loop
        while (dma_flag == 0) {}

        dma_flag = 0;

    } else {
        err = MXC_AES_Decrypt(&req);
        if (err) return err;
    }

    // MXC_AES_Shutdown();

    // bad decrypt function but DEBUG
    if (memcmp(inputData - 1, decryptedData, MXC_AES_DATA_LENGTH) == 0) {
        printf("\nData Verified\n");
        return 0;
    }

    printf("\nData Mismatch");

    return err;
}

/**
 * @brief Secure Receive
 *
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
int secure_receive(uint8_t address, uint8_t *buffer, uint8_t max_len) {
    printf("\n\n* * * AES_decrypt Call * * *\n");
    // Buffer to hold the received encrypted data
    uint8_t encryptedBuffer[max_len];
    memset(encryptedBuffer, 0, sizeof(encryptedBuffer)); // Initialize buffer with zeros
    
    // Receive the encrypted data over I2C
    // int receivedLength = poll_and_receive_packet(address, encryptedBuffer);
    int receivedLength = 1; // DEBUG
    encryptedBuffer[0] = 55; // DEBUG
    encryptedBuffer[1] = 255; // DEBUG, 100 for "encrypt"

    printf("v encrypted buffer v");
    print_array(encryptedBuffer); // DEBUG

    if (receivedLength <= 0) {
        // Error in receiving data or no data received
        return receivedLength;
    }

    // Each segment is 32 bytes (256 bits)
    const uint8_t segmentSize = 32;
    // Calculate the total number of segments received
    uint8_t totalSegments = (receivedLength + segmentSize - 1) / segmentSize;

    for (uint8_t i = 0; i < totalSegments; ++i) {
        // Prepare a segment-sized buffer to hold the current segment for decryption, aligning it as uint32_t
        uint32_t segment[segmentSize / sizeof(uint32_t)];
        memset(segment, 0, sizeof(segment)); // Clear the segment buffer


        // LOOK AT BELOW MEMCOPY

        // Copy the current encrypted segment into the uint32_t aligned buffer
        memcpy(segment, encryptedBuffer + (i * segmentSize), segmentSize);

        printf("v segment v");
        print_32barray(segment); // DEBUG
        
        // Prepare a buffer for the decrypted data, properly typed
        uint32_t decryptedSegment[segmentSize / sizeof(uint32_t)];
        memset(decryptedSegment, 0, sizeof(decryptedSegment)); // Clear the decrypted segment buffer

        // Decrypt the segments
        int decryptResult = AES_decrypt(0, MXC_AES_256BITS, MXC_AES_DECRYPT_EXT_KEY, segment, decryptedSegment);

        printf("v segment v");
        print_32barray(segment); // DEBUG

        printf("v decrypt segment v");
        print_32barray(decryptedSegment); // DEBUG

        if (decryptResult != 0) {
            // Handle decryption error
            return decryptResult; // or another appropriate error code
        }
        
        // Copy the decrypted data back to the buffer, converting it to uint8_t* for the caller
        // Ensure not to exceed max_len
        int bytesToCopy = segmentSize;
        if ((i * segmentSize + segmentSize) > max_len) {
            bytesToCopy = max_len % segmentSize;
        }
        memcpy(buffer + (i * segmentSize), decryptedSegment, bytesToCopy);
    }
    
    // Return the length of the decrypted data
    return receivedLength; // This assumes the decrypted data size equals the encrypted data size
}

int main() {
    uint8_t input8bit = 99;
    uint32_t input32bit = 100;

    uint8_t output = 0;

    int err = 0;
    err = secure_send(0, &input8bit, 1);
    // err = AES_decrypt(0, MXC_AES_256BITS, MXC_AES_DECRYPT_EXT_KEY, &input32bit, &output);
    err = secure_receive(0, &output, 8);
    

    printf("Error: %i", err);

    return 0;
}