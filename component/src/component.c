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

volatile int dma_flag = 0;

const mxc_aes_enc_type_t external_aes_key[] = EXTERNAL_AES_KEY;

/******************************* POST BOOT FUNCTIONALITY
 * *********************************/
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

/******************************* FUNCTION DEFINITIONS
 * *********************************/

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
    mxc_aes_req_t* req;
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

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint32_t len =
        sprintf((char *)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) +
        1;

    // Calculate the number of 128-bit segments
    uint32_t num_segments =
        (len + 15) / 16; // Round up to the nearest 128-bit segment

    // Encrypt each 128-bit segment of len and concatenate them together
    for (uint32_t i = 0; i < num_segments; ++i) {
        AES_encrypt(0, MXC_AES_256BITS); // Encrypt 128-bit segment (16 bytes)
    }

    // Send the encrypted len and the attestation data
    send_packet_and_ack(len, transmit_buffer);
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
