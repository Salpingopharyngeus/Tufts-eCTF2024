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
#include <string.h>

#include "aes.h"
#include "aes_regs.h"
#include "dma.h"
#include "mxc_device.h"

#include "board_link.h"
#include "host_messaging.h"
#include "simple_i2c_peripheral.h"

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
#endif

// AES encryption related includes
#include "aes.h"
#include "aes_regs.h"
#include "aes_functions.h"

#include "../../deployment/global_secrets.h"

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

#define MXC_AES_DATA_LENGTH 8 // 4 words

#define MXC_AES_ENC_DATA_LENGTH 8 // Always multiple of 4
#define ATTESTATION_SIZE 212
//(equal to or greater than MXC_AES_DATA_LENGTH)

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
    uint8_t params[MAX_I2C_MESSAGE_LEN - 1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS
 * **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES
 * **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

uint32_t inputData[MXC_AES_DATA_LENGTH] = {0x873AC125, 0x2F45A7C8, 0x3EB7190,
                                           0x486FA931, 0x94AE56F2, 0x89B4D0C1,
                                           0x2F45A7C8, 0x3EB7190};
uint32_t encryptedData[MXC_AES_ENC_DATA_LENGTH] = {0};
uint32_t decryptedData[MXC_AES_DATA_LENGTH] = {0};
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
 * Securely send data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
void secure_send(uint8_t *buffer, uint8_t len) {
    send_packet_and_ack(len, buffer);
}

/**
 * @brief Secure Receive
 *
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
int secure_receive(uint8_t *buffer) { return wait_and_receive_packet(buffer); }

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
    // LED loop to show that boot occurred
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

void print_uint32_buffer(uint32_t *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%u ", buffer[i]);
    }
    printf("\n");
}

void print_uint8_buffer_as_string(uint8_t *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%c", buffer[i]);
    }
    printf("\n");
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message *command = (command_message *)receive_buffer;

    // Output to application processor dependent on command received
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
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void *)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message *packet = (scan_message *)transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    validate_message *packet = (validate_message *)transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data

    // Construct Attestation String Data
    size_t attest_loc_size = sizeof(ATTESTATION_LOC) - 1;
    size_t attest_date_size = sizeof(ATTESTATION_DATE) - 1;
    size_t attest_cust_size = sizeof(ATTESTATION_CUSTOMER) - 1;
 
    
    size_t ATTEST_SIZE = 224;//attest_loc_size + attest_date_size + attest_cust_size + 21;

    char attestation_data[ATTEST_SIZE]; // Assuming a sufficiently large buffer size
    sprintf(attestation_data, "LOC>%s\nDATE>%s\nCUST>%s\n", ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER);

    print_debug("Attestation data: \n");
    print_debug("%s\n", attestation_data);

    // Store Attestation Data in uint8_t* buffer
    uint8_t temp_buffer[ATTEST_SIZE];
    memset(temp_buffer, 0, ATTEST_SIZE);
    memcpy(temp_buffer, attestation_data, ATTEST_SIZE);

    // print_debug("uint8_t representation before encryption: \n");
    // print_hex_debug(temp_buffer, ATTEST_SIZE);

    // Store Attestation Data in uint32_t* buffer --> from uint8_t* buffer
    uint32_t uint32_temp[ATTEST_SIZE / sizeof(uint32_t)];
    memset(uint32_temp, 0, ATTEST_SIZE / sizeof(uint32_t));
    uint8_to_uint32(temp_buffer, sizeof(temp_buffer), uint32_temp, sizeof(uint32_temp) / sizeof(uint32_t));

    // CHECK CONTENT OF UINT32_T BUFFER BEFORE ENCRYPTION
    print_debug("CONTENT OF UINT32_T BUFFER BEFORE ENCRYPTION: \n");
    print_uint32_buffer(uint32_temp, MAX_I2C_MESSAGE_LEN / sizeof(uint32_t));

    // Initialize uint32_t transmit buffer
    uint32_t uint32_transmit_buffer[ATTEST_SIZE/sizeof(uint32_t)];
    memset(uint32_transmit_buffer, 0, ATTEST_SIZE/sizeof(uint32_t));

    // Set the external encryption key
    MXC_AES_SetExtKey(external_aes_key, MXC_AES_128BITS);

    // Encrypt contents of uint32_t representation of attestation data and store result in uint32_t transmit buffer
    int aes_success = AES_encrypt(0, MXC_AES_256BITS, uint32_temp, uint32_transmit_buffer);

    // Convert uint32_t transmit buffer content to uint8_t representation
    size_t num_elements = sizeof(uint32_transmit_buffer) / sizeof(uint32_t);
    size_t uint8_buffer_size = num_elements * sizeof(uint32_t); // Size of the resulting uint8_t buffer
    uint8_t uint8_transmit_buffer[uint8_buffer_size];
    memset(uint8_transmit_buffer, 0, uint8_buffer_size);
    uint32_to_uint8(uint32_transmit_buffer, num_elements, uint8_transmit_buffer, uint8_buffer_size);


    ///// TEST DECRYPTION ///////

    uint32_t uint32_test_buffer[ATTEST_SIZE/sizeof(uint32_t)];
    memset(uint32_test_buffer, 0, ATTEST_SIZE/sizeof(uint32_t));
    uint8_to_uint32(uint8_transmit_buffer, sizeof(uint8_transmit_buffer), uint32_test_buffer, sizeof(uint32_test_buffer) / sizeof(uint32_t));
    
    uint32_t uint32_decrypt_buffer[ATTEST_SIZE/sizeof(uint32_t)];
    memset(uint32_decrypt_buffer, 0, ATTEST_SIZE/sizeof(uint32_t));

    int decrypt_success = AES_decrypt(0, MXC_AES_256BITS, MXC_AES_DECRYPT_INT_KEY, uint32_test_buffer, uint32_decrypt_buffer);

    //CHECK CONTENT OF UINT32_T DECRYPTED BUFFER
    print_debug("CONTENT OF UINT32_T BUFFER AFTER DECRYPTION: \n");
    print_uint32_buffer(uint32_decrypt_buffer, MAX_I2C_MESSAGE_LEN / sizeof(uint32_t));
    

    //Debug uint32_t transmit buffer content using uint8_t representation
    size_t num_elements2 = sizeof(uint32_decrypt_buffer) / sizeof(uint32_t);
    size_t uint8_buffer_size2 = num_elements2 * sizeof(uint32_t); // Size of the resulting uint8_t buffer
    uint8_t uint8_debug_buffer2[uint8_buffer_size2];
    memset(uint8_debug_buffer2, 0, uint8_buffer_size2);
    uint32_to_uint8(uint32_decrypt_buffer, num_elements2, uint8_debug_buffer2, uint8_buffer_size2);

    print_debug("DECRYPTED MESSAGE: \n");
    //print_hex_debug(uint8_debug_buffer2, ATTEST_SIZE);
    print_uint8_buffer_as_string(uint8_debug_buffer2, ATTEST_SIZE);

    // print_debug("TRANSMIT BUFFER: \n");
    // print_hex_debug(uint8_transmit_buffer, ATTEST_SIZE);
    // send_packet_and_ack(ATTEST_SIZE, uint8_transmit_buffer);
}
/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");

    // Enable Global Interrupts
    __enable_irq();

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);

    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);

        component_process_cmd();
    }
}