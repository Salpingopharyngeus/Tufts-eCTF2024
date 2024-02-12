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
#endif

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
#define MAX_KEY_LENGTH 256

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
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

typedef struct {
    command_message c_message;
    uint32_t key;
} outer_layer;
/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);
void print(const char *message);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

bool arrays_equal(uint8_t params1[MAX_I2C_MESSAGE_LEN-1], uint8_t params2[MAX_I2C_MESSAGE_LEN-1]) {
    for (int i = 0; i < MAX_I2C_MESSAGE_LEN-1; i++) {
        if (params1[i] != params2[i]) {
            // Found elements that are not equal, so the arrays are not identical
            return false;
        }
    }
    // Reached the end without finding any differences
    return true;
}

char* array_to_str(uint8_t array[MAX_I2C_MESSAGE_LEN-1]) {
    int maxStrLen = (MAX_I2C_MESSAGE_LEN - 1) * 2 + 1;
    char* paramsStr[maxStrLen];
    paramsStr[0] = '\0'; 
    char tempStr[3];

    for (int i = 0; i < MAX_I2C_MESSAGE_LEN - 1; i++) {
        snprintf(tempStr, sizeof(tempStr), "%02X", array[i]);
        strncat(paramsStr, tempStr, 3); 
    }
   return paramsStr;
}


void print(const char *message) {
    // Open the serial port
    FILE *serial = fopen("/dev/tty.usbmodem21302", "w");
    if (serial == NULL) {
        perror("Error opening serial port");
        return;
    }

    // Send the message over the serial port
    fprintf(serial, "%s\n", message);

    // Close the serial port
    fclose(serial);
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
    send_packet_and_ack(len, buffer); 
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
    return wait_and_receive_packet(buffer);
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
    //print("processing command packet");
    //if (valid_packet(receive_buffer)) {
    // outer_layer* outer = (outer_layer*) receive_buffer;
    // command_message command = outer->c_message;
    // uint32_t value = outer->key;
    command_message* command = (command_message*) receive_buffer;
    // Output to application processor dependent on command received
    //if (!strcmp("test", "test")) {
    switch (command->opcode) {
        case COMPONENT_CMD_BOOT:
            process_boot();
            break;
        case COMPONENT_CMD_SCAN:
            process_scan();
            break;
        case COMPONENT_CMD_VALIDATE:
            char* key = "hello";
            uint8_t hash_out[HASH_SIZE];
            hash(key, BLOCK_SIZE, hash_out);
            uint8_t recreate_hash[MAX_I2C_MESSAGE_LEN-1];
            //print("Recreating hash!");
            
            //print("checking hashes!");
            char* recreated_hash_to_str = array_to_str(recreate_hash);
            char* received_hash_to_str = array_to_str(command->params);
            if (strcmp(recreated_hash_to_str, received_hash_to_str) != 0) {
                free(recreated_hash_to_str);
                free(received_hash_to_str);
                break;
            }
            process_validate();
            break;
        case COMPONENT_CMD_ATTEST:
            process_attest();
            break;
        default:
            //print("Error: Unrecognized command received");
            break;
    }
    //}
    // }else {
    //     print_error("INVALID PACKET! POTENTIAL IMPOSTER!!!");
    // }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    send_packet_and_ack(len, transmit_buffer);
}

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
        wait_and_receive_packet(receive_buffer);
        component_process_cmd();
    }
}
