/**
 * @file component.c
 * @author Jacob Doll
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2024 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
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
#include "md5.h"
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

#include "aes.h"
#include "aes_regs.h"
#include "dma.h"
#include "mxc_device.h"

// Includes from containerized build
#include "../../deployment/global_secrets.h"
#include "ectf_params.h"

#ifdef POST_BOOT
#include "board.h"
#include "dma.h"
#include "led.h"
#include "mxc_device.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mxc_device.h"
#include "board.h"
#include "dma.h"
#endif



// Define the maximum length of encrypted data
#define HASH_SIZE 16
#include "aes_functions.h"

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


/******************************** TYPE DEFINITIONS
 * ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS
 * ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t authkey[HASH_SIZE];
    uint32_t random_number;
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


/********************************* GLOBAL VARIABLES
 * **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
uint32_t assigned_random_number = 0;


/********************************* UTILITY FUNCTIONS  **********************************/

/**
 * @brief hash_equal
 * 
 * @param hash1: uint8_t*, uint8_t array representation of hash1
 * @param hash2: uint8_t*, uint8_t array representation of hash2
 * 
 * @return bool: true if hash1 == hash2; false otherwise.
 * Check equality of two uint8*t buffers containing hash value
*/
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

// AES request
mxc_aes_req_t req;

const uint8_t external_aes_key[] = EXTERNAL_AES_KEY;

/******************************* POST BOOT FUNCTIONALITY **********************************/
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
    // Ensure component is not initializing communication with AP.
    if (assigned_random_number == 0){
        print_error("Component attempting to initiate communication with AP first!\n");
        return ERROR_RETURN;
    }

    // Set Maximum Packet Size for Secure Send
    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;
    
    // Ensure length of data to send does not exceed limits
    if (len > MAX_PACKET_SIZE - HASH_SIZE - sizeof(uint8_t) - sizeof(uint32_t)) {
        print_error("Message too long");
        return ERROR_RETURN;
    }

    // Create secure packet
    uint8_t temp_buffer[MAX_PACKET_SIZE]; // Declare without initialization
    uint32_t random_number = assigned_random_number;
    memset(temp_buffer, 0, MAX_PACKET_SIZE); // Initialize buffer to zero

    size_t hash_position = MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t) - HASH_SIZE;
    size_t data_len_position = MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t);
    size_t random_number_position = MAX_PACKET_SIZE - sizeof(uint32_t);
    memcpy(temp_buffer, buffer, len);
    
    size_t key_len = strlen(KEY);

     // Build Authenication Hash
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

    uint8_t hash_out[HASH_SIZE];
    md5hash(data_key_randnum, data_key_randnum_len, hash_out);
    free(data_key_randnum);

    // Add security attributes to packet
    memcpy(temp_buffer + hash_position, hash_out, HASH_SIZE); // add authentication hash
    temp_buffer[data_len_position] = len; // add data length
    memcpy(temp_buffer + random_number_position, &random_number, sizeof(uint32_t)); // add random number
    
    // Send packet
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
    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;

    uint8_t len = wait_and_receive_packet(buffer);
    
    // Extract the random number
    uint32_t random_number;
    memcpy(&random_number, buffer + MAX_PACKET_SIZE - sizeof(uint32_t), sizeof(uint32_t));

    // Extract the data length
    uint8_t data_len = buffer[MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t)];

    // Extract the hash
    uint8_t received_hash[HASH_SIZE];
    memcpy(received_hash, buffer + MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t) - HASH_SIZE, HASH_SIZE);

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

    uint8_t check_hash[HASH_SIZE];
    md5hash(data_key_randnum, data_key_randnum_len, check_hash);
    free(data_key_randnum);
    
    // Check hash for integrity and authenticity of the message
    if(!hash_equal(received_hash, check_hash)){
        print_error("Could not validate AP\n");
        return ERROR_RETURN;
    }

    // Save assigned random_number from AP
    assigned_random_number = random_number;
    
    // Extract the original message
    // uint8_t original_message[data_len + 1]; // Add one for the null terminator
    // memcpy(original_message, buffer, data_len);
    // original_message[data_len] = '\0'; // Null-terminate the string

    // Return number of bytes of original data
    return data_len;
}

/******************************* FUNCTION DEFINITIONS **********************************/

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
    //LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
#endif
}

void uint8_to_uint32(const uint8_t* uint8_buffer, size_t uint8_buffer_size, uint32_t* uint32_buffer, size_t num_elements) {
    // Check if the buffer sizes are compatible
    if (uint8_buffer_size % sizeof(uint32_t) != 0 || uint8_buffer_size / sizeof(uint32_t) != num_elements) {
        // Handle mismatched buffer sizes
        fprintf(stderr, "Buffer sizes are not compatible\n");
        return;
    }
    
    // Copy bytes from the uint8_t buffer to the uint32_t buffer
    for (size_t i = 0; i < num_elements; i++) {
        // Reinterpret the memory layout of the next set of bytes as a uint32_t value
        uint32_t value = *((const uint32_t*)(uint8_buffer + i * sizeof(uint32_t)));
        // Store the uint32_t value in the uint32_t buffer
        uint32_buffer[i] = value;
    }
}

void uint32_to_uint8(const uint32_t* uint32_buffer, size_t num_elements, uint8_t* uint8_buffer, size_t uint8_buffer_size) {
    // Ensure the provided uint8_buffer has enough space
    size_t required_size = num_elements * sizeof(uint32_t);
    if (uint8_buffer_size < required_size) {
        printf("Error: Insufficient space in uint8_buffer\n");
        return;
    }

    // Iterate over each uint32_t value in the buffer
    for (size_t i = 0; i < num_elements; i++) {
        // Extract the bytes from the uint32_t value
        uint32_t value = uint32_buffer[i];
        for (size_t j = 0; j < sizeof(uint32_t); j++) {
            // Store each byte of the uint32_t value in the uint8_t buffer
            uint8_buffer[i * sizeof(uint32_t) + j] = (uint8_t)(value >> (j * 8));
        }
    }
}

// Handle a transaction from the AP
void component_process_cmd() {
    // Output to application processor dependent on command received
    command_message* command = (command_message*) receive_buffer;

    print_debug("Received random number: %u\n", (uint32_t) command->random_number);
    //print_hex_debug(command->random_number, sizeof(command->random_number));
    
    // Recreate authkey hash to check authenticity of receive_buffer
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    memset(hash_out, 0, HASH_SIZE);
    md5hash(key, HASH_SIZE, hash_out);

    // Check validity of authkey hash
    if (hash_equal(command->authkey, hash_out)){
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
                print_error("Error: Unrecognized command received");
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

    // Attach authentication hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    md5hash(key, HASH_SIZE, hash_out);
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
    scan_message *packet = (scan_message *)transmit_buffer;
    packet->component_id = COMPONENT_ID;

    // Attach authentication hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    md5hash(key, HASH_SIZE, hash_out);
    memcpy(packet->authkey, hash_out, HASH_SIZE);
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component I
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    
    // Attach authentication hash
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    md5hash(key, HASH_SIZE, hash_out);
    memcpy(packet->authkey, hash_out, HASH_SIZE);
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

// Modify the process_attest function to encrypt the len variable
void process_attest() {
    // The AP requested attestation. Respond with the attestation data

    // Construct Attestation String Data
    uint8_t attest_loc_size = sizeof(ATTESTATION_LOC);
    uint8_t attest_date_size = sizeof(ATTESTATION_DATE);
    uint8_t attest_cust_size = sizeof(ATTESTATION_CUSTOMER);

    size_t ATTEST_SIZE = 224;
    uint8_t fixed_size = 17;
    uint8_t EXACT_SIZE = attest_loc_size + attest_date_size + attest_cust_size + fixed_size;
    
    char attestation_data[ATTEST_SIZE]; // Assuming a sufficiently large buffer size
    sprintf(attestation_data, "LOC>%s\nDATE>%s\nCUST>%s\n", ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER);

    // Store Attestation Data in uint8_t* buffer
    uint8_t temp_buffer[ATTEST_SIZE];
    memset(temp_buffer, 0, ATTEST_SIZE);
    memcpy(temp_buffer, attestation_data, ATTEST_SIZE);

    // Store Attestation Data in uint32_t* buffer --> from uint8_t* buffer
    uint32_t uint32_temp[ATTEST_SIZE / sizeof(uint32_t)];
    memset(uint32_temp, 0, ATTEST_SIZE / sizeof(uint32_t));
    uint8_to_uint32(temp_buffer, sizeof(temp_buffer), uint32_temp, sizeof(uint32_temp) / sizeof(uint32_t));

    // Initialize uint32_t transmit buffer
    uint32_t uint32_transmit_buffer[ATTEST_SIZE/sizeof(uint32_t)];
    memset(uint32_transmit_buffer, 0, ATTEST_SIZE/sizeof(uint32_t));

    // Set the external encryption key
    MXC_AES_SetExtKey(external_aes_key, MXC_AES_128BITS);

    // Encrypt contents of uint32_t representation of attestation data and store result in uint32_t transmit buffer
    int aes_success = AES_encrypt(0, MXC_AES_128BITS, uint32_temp, uint32_transmit_buffer);

    // Convert uint32_t transmit buffer content to uint8_t representation
    size_t num_elements = sizeof(uint32_transmit_buffer) / sizeof(uint32_t);
    size_t uint8_buffer_size = num_elements * sizeof(uint32_t); // Size of the resulting uint8_t buffer
    uint8_t uint8_transmit_buffer[uint8_buffer_size];
    memset(uint8_transmit_buffer, 0, uint8_buffer_size);
    uint32_to_uint8(uint32_transmit_buffer, num_elements, uint8_transmit_buffer, uint8_buffer_size);

    send_packet_and_ack(uint8_buffer_size, uint8_transmit_buffer);
}



// hardware intit function

void init() {
// hardware

    uint8_t usn[MXC_SYS_USN_LEN];

    int usn_error = MXC_SYS_GetUSN(usn, NULL);

    if (usn_error != E_NO_ERROR) {
        // kill urself
        //call to restart
        // Instead of printing, append the message to the buffer
        //appendToBuffer("womp womp\n");
        print_debug("womp womp");
        //MXC_SYS_Reset_Periph(MXC_SYS_RESET0_SYS);
        return ERROR_RETURN;

    } else {
        //appendToBuffer("yay!\n");
        print_debug("yay! from component");
    }
}
/*********************************** MAIN *************************************/

int main(void) {
    //print("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();

    // Initialize Component

    // hardware
    init();
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);


    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);
        component_process_cmd();
    }
}