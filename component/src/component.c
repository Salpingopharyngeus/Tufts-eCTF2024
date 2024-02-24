/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "host_messaging.h"
#include "simple_i2c_peripheral.h"
#include "board_link.h"
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mxc_device.h"
#include "board.h"
#include "dma.h"
#endif

// AES encryption related includes
#include "aes.h"
#include "aes_regs.h"

// Define the maximum length of encrypted data
#define MXC_AES_ENC_DATA_LENGTH 256

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t authkey[HASH_SIZE];

} command_message;

typedef struct {
    uint32_t component_id;
    uint8_t authkey[HASH_SIZE];
} validate_message;

typedef struct {
    uint32_t component_id;
    uint8_t authkey[HASH_SIZE];
} scan_message;



/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);
void print(const char *message);

// AES encryption function
int AES_encrypt(uint8_t *data, uint32_t data_length, mxc_aes_keys_t key);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
uint32_t encryptedData[MXC_AES_ENC_DATA_LENGTH] = {0};
uint32_t assigned_random_number = 0;


/********************************* UTILITY FUNCTIONS  **********************************/
// Check equality of two uint8_t* values holding hash value
bool hash_equal(uint8_t* hash1, uint8_t* hash2) {
    size_t array_size = sizeof(hash1) / sizeof(hash1[0]);
    for (int i = 0; i < array_size; i++) {
        if (hash1[i] != hash2[i]) {
            // Found elements that are not equal, so the arrays are not identical
            return false;
        }
    }
    // Reached the end without finding any differences
    return true;
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    print_debug("COMPONENT SECURE SEND CALLED!\n");
    if (assigned_random_number == 0){
        print_error("Component attempting to initiate communication with AP first!\n");
        return ERROR_RETURN;
    }

    // Set maximum secure send packet size
    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;
    
    if (len > MAX_PACKET_SIZE - HASH_SIZE - sizeof(uint8_t) - sizeof(uint32_t)) {
        print_error("Message too long");
        return ERROR_RETURN;
    }

    uint8_t temp_buffer[MAX_PACKET_SIZE]; // Declare without initialization
    uint32_t random_number = assigned_random_number;

    print_debug("Random Number to Send: %u\n", random_number); 
    memset(temp_buffer, 0, MAX_PACKET_SIZE); // Initialize buffer to zero

    size_t hash_position = MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t) - HASH_SIZE; // Hash is 16 bytes before the last 5 bytes
    size_t data_len_position = MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t); // Data length is 1 byte before the last 4 bytes
    size_t random_number_position = MAX_PACKET_SIZE - sizeof(uint32_t); // Random number is the last 4 bytes

    // Copy the original data into temp_buffer, ensuring not to overwrite the hash, data length, and random number positions
    memcpy(temp_buffer, buffer, len);

    // Assuming KEY is defined and has a known size for the hash operation
    size_t key_len = strlen(KEY);

    // Prepare data for hashing (data + key)
    size_t data_key_randnum_len = len + key_len + sizeof(uint32_t);
    uint8_t* data_key_randnum = malloc(data_key_randnum_len);
    memset(data_key_randnum, 0, data_key_randnum_len);
    if (!data_key_randnum) {
        print_error("Memory allocation failed for data_key_randnum");
        return ERROR_RETURN;
    }
    memcpy(data_key_randnum, buffer, len);
    memcpy(data_key_randnum + len, KEY, key_len);
    memcpy(data_key_randnum + len + sizeof(uint32_t), &random_number, sizeof(uint32_t));
    
    print_debug("BEFORE HASH: \n");
    print_hex_debug(data_key_randnum, data_key_randnum_len);
    print_debug("\n");
    // Hash data+key
    uint8_t hash_out[HASH_SIZE];
    hash(data_key_randnum, data_key_randnum_len, hash_out);
    free(data_key_randnum);
    
    print_debug("Component Authentication Hash:\n");
    print_hex_debug(hash_out, HASH_SIZE);
    print_debug("----------------------------------------\n");

    // Append hash, data length, and random number to the buffer at their specified positions
    memcpy(temp_buffer + hash_position, hash_out, HASH_SIZE);
    temp_buffer[data_len_position] = len; // Ensure len is suitable for a uint8_t
     // Example random number
    memcpy(temp_buffer + random_number_position, &random_number, sizeof(uint32_t));
    send_packet_and_ack(MAX_PACKET_SIZE, temp_buffer); 
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    print_debug("COMPONENT SECURE RECEIVE CALLED!\n");

    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;

    uint8_t len = wait_and_receive_packet(buffer); // Adjust this part according to your actual implementation

    // Extract the random number
    uint32_t random_number;
    memcpy(&random_number, buffer + MAX_PACKET_SIZE - sizeof(uint32_t), sizeof(uint32_t));
    print_debug("Random number received: %u\n", random_number);

    // Extract the data length
    uint8_t data_len = buffer[MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t)];

    // Extract the hash
    uint8_t received_hash[HASH_SIZE];
    memcpy(received_hash, buffer + MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t) - HASH_SIZE, HASH_SIZE);
    print_debug("Received Hash: \n");
    print_hex_debug(received_hash, HASH_SIZE);

    // Recreate authkey hash to check authenticity of receive_buffer
    size_t key_len = strlen(KEY);

    size_t data_key_randnum_len = data_len + key_len + sizeof(uint32_t);
    uint8_t* data_key_randnum = malloc(data_key_randnum_len);
    memset(data_key_randnum, 0, data_key_randnum_len);
    if (!data_key_randnum) {
        print_error("Memory allocation failed for data_key_randnum");
        return ERROR_RETURN;
    }
    memcpy(data_key_randnum, buffer, data_len);
    memcpy(data_key_randnum + data_len, KEY, key_len);
    memcpy(data_key_randnum + data_len + sizeof(uint32_t), &random_number, sizeof(uint32_t));

    print_debug("BEFORE HASH: \n");
    print_hex_debug(data_key_randnum, data_key_randnum_len);
    print_debug("\n");
    // Hash data+key
    uint8_t check_hash[HASH_SIZE];
    hash(data_key_randnum, data_key_randnum_len, check_hash);
    free(data_key_randnum);
    
    print_debug("Check Hash: \n");
    print_hex_debug(check_hash, HASH_SIZE);
    
    // Check hash for integrity and authenticity of the message
    if(!hash_equal(received_hash, check_hash)){
        print_error("Could not validate AP\n");
        return ERROR_RETURN;
    }
    assigned_random_number = random_number;
    // Extract the original message
    uint8_t original_message[data_len + 1]; // Add one for the null terminator
    memcpy(original_message, buffer, data_len);
    original_message[data_len] = '\0'; // Null-terminate the string

    print_debug("Original message: \n");
    print_debug("%s\n", original_message);
    print_debug("----------------------------------------\n");

    secure_send(original_message, data_len);
    return data_len;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    // while (1) {
    //     LED_On(LED1);
    //     MXC_Delay(500000);
    //     LED_On(LED2);
    //     MXC_Delay(500000);
    //     LED_On(LED3);
    //     MXC_Delay(500000);
    //     LED_Off(LED1);
    //     MXC_Delay(500000);
    //     LED_Off(LED2);
    //     MXC_Delay(500000);
    //     LED_Off(LED3);
    //     MXC_Delay(500000);
    // }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    // Output to application processor dependent on command received
    command_message* command = (command_message*) receive_buffer;
    
    // Recreate authkey hash to check authenticity of receive_buffer
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    hash(key, HASH_SIZE, hash_out);

    // Check validity of authkey hash
    if (hash_equal(command->authkey, hash_out)){
        print_debug("AP validated\n");
        switch (command->opcode) {
            case COMPONENT_CMD_BOOT:
                process_boot();
                break;
            case COMPONENT_CMD_SCAN:
                process_scan();
                break;
            case COMPONENT_CMD_VALIDATE:     
                process_validate();
                break;
            case COMPONENT_CMD_ATTEST:
                process_attest();
                break;
            default:
                //print("Error: Unrecognized command received");
                break;
        }
    }else{
        print_error("Conflicting Authentication Hashes!\n");
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;

    // Send authkey hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    hash(key, HASH_SIZE, hash_out);
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    memcpy((void*)transmit_buffer + len, hash_out, HASH_SIZE);

    // Calculate the total length of data to be sent
    uint8_t total_len = len + HASH_SIZE;

    // Send the data
    send_packet_and_ack(total_len, transmit_buffer);
    
    // Call the boot function
    boot();
}

void process_scan() {
    
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;

    // Send authkey hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    hash(key, BLOCK_SIZE, hash_out);
    memcpy(packet->authkey, hash_out, HASH_SIZE);
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component I
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    
    // Send authkey hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    hash(key, BLOCK_SIZE, hash_out);
    memcpy(packet->authkey, hash_out, HASH_SIZE);
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

// Modify the process_attest function to encrypt the len variable
void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;

    // Encrypt the len variable
    // AES_encrypt(&len, sizeof(len), MXC_AES_128BITS);
    // send_packet_and_ack(len, transmit_buffer);
    
    // send authkey hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    hash(key, HASH_SIZE, hash_out);

    memcpy((void*)transmit_buffer + len, hash_out, HASH_SIZE);
    // Calculate the total length of data to be sent
    uint8_t total_len = len + HASH_SIZE;

    send_packet_and_ack(total_len, transmit_buffer);
}

// AES encryption function implementation
// int AES_encrypt(uint8_t *data, uint32_t data_length, mxc_aes_keys_t key)
// {
//     mxc_aes_req_t req;

//     // Set the length of the input data
//     req.length = (data_length + 3) / 4; // Round up to the nearest word

//     // Set the input data and result data pointers
//     req.inputData = (uint32_t *)data;
//     req.resultData = encryptedData;

//     // Set the key size and encryption mode
//     req.keySize = key;
//     req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

//     // Initialize AES
//     MXC_AES_Init();

//     // Perform AES encryption
//     MXC_AES_Encrypt(&req);

//     // Shutdown AES after encryption
//     MXC_AES_Shutdown();

//     return E_NO_ERROR;
// }


/*********************************** MAIN *************************************/

int main(void) {
    //print("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        //wait_and_receive_packet(receive_buffer);
        secure_receive(receive_buffer);
        //component_process_cmd();
    }
}