/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "board_link.h"
#include "host_messaging.h"
#include "dictionary.h"
#include "buffer.h"
#include "md5.h"
#include "simple_flash.h"
#include "eddsa.h"
#include "bcrypt.h"

#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif
#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#include "bcrypt.h"
#endif
// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"
#include <time.h>
#include "trng_util.h"

#include "aes.h"
#include "aes_regs.h"
#include "dma.h"
#include "mxc_device.h"
#include "aes_functions.h"
#include "eddsa.h"

// testing
#include <string.h> // for strncat and strlen

// end testing

#define AES_KEY_SIZE 16

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/


// Flash Macros
#define FLASH_ADDR                                                             \
    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
#define ATTESTATION_SIZE 212

// Hash Digest
#define HASH_SIZE 16


/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode; // 1 byte
    uint8_t authkey[HASH_SIZE]; // 16 bytes
    uint8_t random_number[4]; //4 bytes for the RNG
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id; // 4 byte
    uint8_t authkey[HASH_SIZE]; // 16 bytes
    uint8_t random_number[4]; //4 bytes for the RNG
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id; // 4 byte
    uint8_t authkey[HASH_SIZE]; // 16 bytes
    uint8_t random_number[4];
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic; // 4 bytes
    uint32_t component_cnt; // 4 bytes
    uint32_t component_ids[32]; // 4 bytes
} flash_entry;

typedef struct {
    uint8_t opcode;
    uint8_t public_key[X25519_KEY_LEN];
} ap_public_key_packet;

typedef struct {
    uint8_t public_key[X25519_KEY_LEN];
} comp_public_key;


// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST,
    COMPONENT_AP_KEY_EXCHANGE,
    COMPONENT_AP_HASH_KEY_EXCHANGE
} component_cmd_t;


/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;
Dictionary dict;
Uint32Buffer* random_number_hist;
//const uint8_t external_aes_key[] = EXTERNAL_AES_KEY;
bool valid_device = false; 
size_t PACKET_SIZE = HASH_SIZE + sizeof(uint8_t) + sizeof(uint32_t);
uint8_t KEY[4];

/********************************* REFERENCE FLAG ************************************/
// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// NOTE: you're not allowed to do this in your code
// Remove this in your design

/********************************* UTILITY FUNCTIONS  **********************************/

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
/**
 * @brief uint8_array_to_uint32
 * 
 * @param byte_array: uint8_t buffer representatin of a uint32_t number
 * 
 * @return uint32_t: uint32_t representation of uint8_t buffer
*/
uint32_t uint8_array_to_uint32(const uint8_t* byte_array) {
    uint32_t value = 0;
    value |= ((uint32_t)byte_array[0] << 24);
    value |= ((uint32_t)byte_array[1] << 16);
    value |= ((uint32_t)byte_array[2] << 8);
    value |= ((uint32_t)byte_array[3]);
    return value;
}

//buffer conversion function:
void uint32_to_uint8_array(uint32_t value, uint8_t* byte_array) {
    // Ensure the byte_array has space for 4 bytes.
    byte_array[0] = (value >> 24) & 0xFF; // Extracts the first byte.
    byte_array[1] = (value >> 16) & 0xFF; // Extracts the second byte.
    byte_array[2] = (value >> 8) & 0xFF;  // Extracts the third byte.
    byte_array[3] = value & 0xFF;         // Extracts the fourth byte.
}

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
    size_t array_size = sizeof(hash1)/sizeof(uint8_t);
    for (int i = 0; i < array_size; i++) {
        if (hash1[i] != hash2[i]) {
            // Found elements that are not equal, so the arrays are not identical
            return false;
        }
    }
    // Reached the end without finding any differences
    return true;
}

/**
 * @brief GenerateAndUseRandomID
 * 
 * @param hash1: uint8_t*, uint8_t array representation of hash1
 * @param hash2: uint8_t*, uint8_t array representation of hash2
 * @return uint32_t: a uint32_t type random number.
 * 
 * Generate and return a random number of type uint32_t.
*/
uint32_t GenerateAndUseRandomID(void) {
    uint32_t randomID;
    TRNG_Init();
    randomID = TRNG_GenerateRandomID();
    TRNG_Shutdown();

    return randomID;
}

/**
 * @brief attach_key
 * 
 * @param command: command_message*, pointer to a command_message struct
 * 
 * Attach hashed authentication key to given command struct object. Assign command->authkey value of hash.  
*/
void attach_key(command_message* command){
    uint8_t hash_out[HASH_SIZE];
    memset(hash_out, 0, HASH_SIZE);
    md5hash(KEY, sizeof(KEY), hash_out);
    memcpy(command->authkey, hash_out, HASH_SIZE);
}

/**
 * @brief attach_random_num
 * 
 * @param command: command_message*, pointer to a command_message struct
 * @param addr: i2c_addr_t, address of component 
 * 
 * Attach hashed authentication key to given command struct object. Assign command->authkey value of hash.  
*/
void attach_random_num(command_message* command, i2c_addr_t addr){
    uint32_t random_num = GenerateAndUseRandomID();
    memset(command->random_number, 0, sizeof(command->random_number));
    uint32_to_uint8_array(random_num, command->random_number);
    addOrUpdate(&dict, addr, random_num);
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/*
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/

int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    initDictionary(&dict);
    
    // Set Maximum Packet Size for Secure Send
    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;

    // Ensure length of data to send does not exceed limits
    if (len > MAX_PACKET_SIZE - HASH_SIZE - sizeof(uint8_t) - sizeof(uint32_t)) {
        print_error("Message too long");
        return ERROR_RETURN;
    }

    // Create secure packet
    uint8_t temp_buffer[MAX_PACKET_SIZE]; // Declare without initialization
    uint32_t random_number = GenerateAndUseRandomID();
    memset(temp_buffer, 0, MAX_PACKET_SIZE); // Initialize buffer to zero

    size_t hash_position = MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t) - HASH_SIZE; 
    size_t data_len_position = MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t); 
    size_t random_number_position = MAX_PACKET_SIZE - sizeof(uint32_t);
    memcpy(temp_buffer, buffer, len);

    size_t key_len = strlen(TEAM_ALIAS);

    // Build Authenication Hash
    size_t data_key_randnum_len = len + key_len + sizeof(uint32_t);
    uint8_t* data_key_randnum = malloc(data_key_randnum_len);
    memset(data_key_randnum, 0, data_key_randnum_len);
    if (!data_key_randnum) {
        print_error("Memory allocation failed for data_key_randnum");
        return ERROR_RETURN;
    }
    memcpy(data_key_randnum, buffer, len);
    memcpy(data_key_randnum + len, TEAM_ALIAS, key_len);
    memcpy(data_key_randnum + len + sizeof(uint32_t), &random_number, sizeof(uint32_t));

    uint8_t hash_out[HASH_SIZE];
    md5hash(data_key_randnum, data_key_randnum_len, hash_out);
    free(data_key_randnum);

    // Add security attributes to packet
    memcpy(temp_buffer + hash_position, hash_out, HASH_SIZE); // add authenication hash
    temp_buffer[data_len_position] = len; // add data length
    memcpy(temp_buffer + random_number_position, &random_number, sizeof(uint32_t)); // add random number

    // Update random number assignment for component
    addOrUpdate(&dict, address, random_number);

    //print_info("RANDOM NUMBER ASSIGNED TO 0x%02X: %u", address, random_number);

    // Send the packet
    return send_packet(address, MAX_PACKET_SIZE, temp_buffer);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    //print_info("SECURE RECEIVED PACKET FROM COMPONENT!");
    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;

    uint8_t len = poll_and_receive_packet(address, buffer); 

    // Extract the random number
    uint32_t random_number;
    memcpy(&random_number, buffer + MAX_PACKET_SIZE - sizeof(uint32_t), sizeof(uint32_t));
    //print_info("RECEIVED RANDOM NUMBER from 0x%02X: %u", address, random_number);

    int seen = searchUint32Buffer(random_number_hist, random_number);
    if(seen){
        print_error("ERROR: POTENTIAL REPLAY ATTACK!");
        return ERROR_RETURN;
    }else{
        // Save assigned random_number from AP
        appendToUint32Buffer(random_number_hist, random_number);
    }

    // Extract the data length
    uint8_t data_len = buffer[MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t)];

    // Extract the hash
    uint8_t received_hash[HASH_SIZE];
    memcpy(received_hash, buffer + MAX_PACKET_SIZE - sizeof(uint32_t) - sizeof(uint8_t) - HASH_SIZE, HASH_SIZE);

    // Recreate authkey hash to check authenticity of receive_buffer
    size_t key_len = strlen(TEAM_ALIAS);

    size_t data_key_randnum_len = data_len + key_len + sizeof(uint32_t);
    uint8_t* data_key_randnum = malloc(data_key_randnum_len);
    memset(data_key_randnum, 0, data_key_randnum_len);
    if (!data_key_randnum) {
        print_error("Memory allocation failed for data_key_randnum");
        return ERROR_RETURN;
    }
    memcpy(data_key_randnum, buffer, data_len);
    memcpy(data_key_randnum + data_len, TEAM_ALIAS, key_len);
    memcpy(data_key_randnum + data_len + sizeof(uint32_t), &random_number, sizeof(uint32_t));

    uint8_t check_hash[HASH_SIZE];
    md5hash(data_key_randnum, data_key_randnum_len, check_hash);
    free(data_key_randnum);

    // Check hash for integrity and authenticity of the message
    if(!hash_equal(received_hash, check_hash)){
        //print_info("INVALID PACKET FROM COMPONENT!");
        // for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        //     print_info("P>0x%08x\n", flash_status.component_ids[i]);
        // }
        // print_info("address: 0x%02X\n", address);
        // print_info("EXPECTED RANDOM NUMBER: %u", getValue(&dict, address));
        // print_info("RECEIVED RANDOM NUMBER: %u", random_number);
        // print_info("\nRECEIVED HASH: ");
        // for (size_t i = 0; i < sizeof(received_hash); ++i) {
        //     print_info("%02X ", received_hash[i]); // Print each byte in hexadecimal format
        // }
        // print_info("\n--------------------------------------------------\n");
        // print_info("CHECK HASH: ");
        // for (size_t i = 0; i < sizeof(check_hash); ++i) {
        //     print_info("%02X ", check_hash[i]); // Print each byte in hexadecimal format
        // }
        print_error("Could not validate Component\n");
        return ERROR_RETURN;
    }

    // Extract the original message
    // uint8_t original_message[data_len + 1]; // Add one for the null terminator
    // memcpy(original_message, buffer, data_len);
    // original_message[data_len] = '\0'; // Null-terminate the string

    // print_debug("Original message: ");
    // print_debug("%s", original_message);
    // print_debug("----------------------------------------\n");

    // Return number of bytes of original data
    return data_len;
}

// TEST FUNCTIONS
// int issue_secure_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive, uint8_t len) {

//     // Send message
//     int result = secure_send(addr, transmit, len);
//     if (result == ERROR_RETURN) {
//         return ERROR_RETURN;
//     }
    
//     // Receive message
//     int received_bytes = secure_receive(addr, receive);
//     if (received_bytes == ERROR_RETURN) {
//         return ERROR_RETURN;
//     }
//     return received_bytes;
//     //return result;
// }

// int test_secure_send() {
//     print_debug("test secure send called");
//     // Buffers for board link communication
//     uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
//     uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    
//     // Send validate command to each component
//     for (unsigned i = 0; i < flash_status.component_cnt; i++) {
//         // Set the I2C address of the component
//         i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

//         char* test_message = "Hello, this is a test message";
//         size_t len = strlen(test_message);
//         memcpy(transmit_buffer, test_message, len);

//         // run secure_send
//         int code = issue_secure_cmd(addr, transmit_buffer, receive_buffer, (uint8_t)len);

//         if (code == ERROR_RETURN) {
//             print_error("Failed secure send\n");
//             return ERROR_RETURN;
//         }
//     }
//     freeDictionary(&dict);
//     return SUCCESS_RETURN;
// }

/**
 * @brief Get Provisioned IDs
 *
 * @param uint32_t* buffer
 *
 * @return int: number of ids
 *
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT
 * functionality. This function must be implemented by your team.
 */
int get_provisioned_ids(uint32_t *buffer) {
    memcpy(buffer, flash_status.component_ids,
           flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/


// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {
    /*
     Disabling the peripheral clock disables functionality while also saving power. 
     Associated register states are retained but read and write access is blocked.
    */ 
    MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_SMPHR);
    MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_CPU1);
    //MXC_SYS_ClockEnable()
    // Enable global interrupts
    __enable_irq();

    // Validate device checksum
    uint8_t usn[MXC_SYS_USN_LEN];
    int usn_error = MXC_SYS_GetUSN(usn, NULL);

    if (usn_error != E_NO_ERROR) {
        printf("Invalid Component Hardware Device: Not MAX78000");
        valid_device = false;
        //MXC_SYS_Reset_Periph(MXC_SYS_RESET0_SYS);
        return ERROR_RETURN;

    } else {
        valid_device = true;
        printf("Valid Component Hardware Device: MAX78000");        
    }

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t *)&flash_status,
                      sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids,
               COMPONENT_CNT * sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                           sizeof(flash_entry));
    }

    // Initialize board link interface
    board_link_init();

    // initiliaze dictionary to keep track of sent random numbers
    initDictionary(&dict);
    // Initialize buffer to keep track of history of used random numbers
    random_number_hist = createUint32Buffer(10);
    uint32_t initial_key = 1234567890;
    uint32_to_uint8_array(initial_key, KEY);
}

/**
 * @brief issue_cmd
 * 
 * @param addr: i2c_addr_t, I2C address of receiver
 * @param transmit: uint8_t*, pointer to buffer to transmit data
 * @param receive: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Send a command to a component and receive the result
*/
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive, size_t packet_size) {

    int result = send_packet(addr, packet_size, transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS **********************************/
int exchange_hash_key() {
    // Generate the AES key using the TRNG
    size_t HASH_KEY_SIZE = sizeof(KEY);
    uint32_t random_id = GenerateAndUseRandomID();
    uint32_to_uint8_array(random_id, KEY);

    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Buffers for board link communication
        uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
        uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

        // Generate x25519 key pair for the application processor
        unsigned char ap_public_key[X25519_KEY_LEN];
        unsigned char ap_private_key[X25519_KEY_LEN];
        x25519_base(ap_public_key, ap_private_key);

        // Prepare the packet
        ap_public_key_packet packet;
        packet.opcode = COMPONENT_AP_HASH_KEY_EXCHANGE;
        memcpy(packet.public_key, ap_public_key, sizeof(ap_public_key));
        memcpy(transmit_buffer, &packet, sizeof(packet));

        // Send AP's public key and receive component's public key
        size_t ap_pb_key_packet_size = sizeof(uint8_t) + X25519_KEY_LEN;
        int len = issue_cmd(addr, transmit_buffer, receive_buffer, ap_pb_key_packet_size);
        if (len == ERROR_RETURN) {
            print_error("Could not send AP public key to component\n");
            return ERROR_RETURN;
        }

        // Receive Components public key
        comp_public_key* comp_key = (comp_public_key*) receive_buffer;
        unsigned char comp_pb_key[X25519_KEY_LEN];
        memcpy(comp_pb_key, comp_key->public_key, sizeof(comp_pb_key));

        // Generate the shared secret using x25519 key agreement
        uint8_t shared_secret[X25519_KEY_LEN];
        x25519(shared_secret, ap_private_key, comp_pb_key);

        // Encrypt the AES key using the shared secret
        uint8_t encrypted_hash_key[HASH_KEY_SIZE];
        
        // Add a dummy xor so that this completes in constant time, and doesn't get removed by the compiler
        volatile uint8_t dummy = 0;
        for (int i = 0; i < HASH_KEY_SIZE; i++) {
            encrypted_hash_key[i] = KEY[i] ^ shared_secret[i];
            //Ensures that either way some xor operation occurs.
            dummy ^= encrypted_hash_key[i];
        }

        // Send the encrypted HASH key to the component
        memcpy(transmit_buffer, encrypted_hash_key, sizeof(encrypted_hash_key));
        size_t hash_key_packet_size = HASH_KEY_SIZE;
        len = issue_cmd(addr, transmit_buffer, receive_buffer, hash_key_packet_size);
        if (len == ERROR_RETURN) {
            print_error("Failed to send encrypted AES key to component\n");
            return ERROR_RETURN;
        } 
    }
    return SUCCESS_RETURN;
}

int exchange_aes_key(i2c_addr_t addr) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Generate x25519 key pair for the application processor
    unsigned char ap_public_key[X25519_KEY_LEN];
    unsigned char ap_private_key[X25519_KEY_LEN];
    x25519_base(ap_public_key, ap_private_key);

    // Prepare the packet
    ap_public_key_packet packet;
    packet.opcode = COMPONENT_AP_KEY_EXCHANGE;
    memcpy(packet.public_key, ap_public_key, sizeof(ap_public_key));
    memcpy(transmit_buffer, &packet, sizeof(packet));

    // Send AP's public key and receive component's public key
    size_t ap_pb_key_packet_size = sizeof(uint8_t) + X25519_KEY_LEN;
    int len = issue_cmd(addr, transmit_buffer, receive_buffer, ap_pb_key_packet_size);
    if (len == ERROR_RETURN) {
        print_error("Could not send AP public key to component\n");
        return ERROR_RETURN;
    }

    // Receive Components public key
    comp_public_key* comp_key = (comp_public_key*) receive_buffer;
    unsigned char comp_pb_key[X25519_KEY_LEN];
    memcpy(comp_pb_key, comp_key->public_key, sizeof(comp_pb_key));

    // Generate the AES key using the TRNG
    uint8_t aes_key[AES_KEY_SIZE];
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        aes_key[i] = (uint8_t)GenerateAndUseRandomID();
    }

    // Set External AES Key
    MXC_AES_SetExtKey(aes_key, MXC_AES_128BITS);

    // Generate the shared secret using x25519 key agreement
    uint8_t shared_secret[X25519_KEY_LEN];
    x25519(shared_secret, ap_private_key, comp_pb_key);

    // Encrypt the AES key using the shared secret
    uint8_t encrypted_aes_key[AES_KEY_SIZE];
    //Add a dummy xor so that this completes in constant time, and doesn't get removed by the compiler
    volatile uint8_t dummy = 0;
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        encrypted_aes_key[i] = aes_key[i] ^ shared_secret[i];
        //Ensures that either way some xor operation occurs.
        dummy ^= encrypted_aes_key[i];
    }

    // Send the encrypted AES key to the component
    memcpy(transmit_buffer, encrypted_aes_key, sizeof(encrypted_aes_key));
    size_t aes_key_packet_size = AES_KEY_SIZE;
    len = issue_cmd(addr, transmit_buffer, receive_buffer, aes_key_packet_size);
    if (len == ERROR_RETURN) {
        print_error("Failed to send encrypted AES key to component\n");
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

int validate_components() {
    exchange_hash_key();
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;

        // Attach authentication hash
        attach_key(command);
        attach_random_num(command, addr);

        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer, PACKET_SIZE);

        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }
        validate_message* validate = (validate_message*) receive_buffer;
        uint32_t received_random_num = uint8_array_to_uint32(validate->random_number);

         // Check if random number received is already seen
        int seen = searchUint32Buffer(random_number_hist, received_random_num);

        // Validate received authentication hash
        if(!hash_equal(command->authkey, validate->authkey) || received_random_num != getValue(&dict, addr) || seen){
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }
        // Add received random number to history
        appendToUint32Buffer(random_number_hist, received_random_num);
        
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    // Scan scan command to each component
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;

        // Attach authentication hash
        attach_key(command);
        attach_random_num(command, addr);

        int len = issue_cmd(addr, transmit_buffer, receive_buffer, PACKET_SIZE);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            uint32_t received_random_num = uint8_array_to_uint32(scan->random_number);

            // Check if random number received is already seen
            int seen = searchUint32Buffer(random_number_hist, received_random_num);
            // Validate received authentication hash
            if(!hash_equal(command->authkey, scan->authkey) || received_random_num != getValue(&dict, addr) || seen){
                return ERROR_RETURN;
            }
            // Add received random number to history
            appendToUint32Buffer(random_number_hist, received_random_num);
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int boot_components() {
    exchange_hash_key();
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;

        // Attach authentication hash
        attach_key(command);
        // Attach random number
        attach_random_num(command, addr);

        int len = issue_cmd(addr, transmit_buffer, receive_buffer, PACKET_SIZE);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        uint8_t received_rn_buffer[4];
        size_t start_index = len - sizeof(received_rn_buffer);
        memcpy(received_rn_buffer, receive_buffer + start_index, sizeof(received_rn_buffer));
        uint32_t received_random_num = uint8_array_to_uint32(received_rn_buffer);
    
        int seen = searchUint32Buffer(random_number_hist, received_random_num);

        // Validate received authentication hash
        if (!hash_equal(command->authkey, &receive_buffer[len-HASH_SIZE-4]) || received_random_num != getValue(&dict, addr) || seen){
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }
        // Add received random number to history
        appendToUint32Buffer(random_number_hist, received_random_num);

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    exchange_hash_key();
    // Buffers for board link communication
    size_t PADDED_SIZE = 224;
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN-1];
    uint8_t attestation_data[PADDED_SIZE];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Exchange AES key using RSA
    exchange_aes_key(addr);
    // Create command message
    command_message *command = (command_message *)transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Attach authentication hash
    attach_key(command);
    // Attach random number
    attach_random_num(command, addr);

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer, PACKET_SIZE);

    uint8_t EXACT_SIZE = receive_buffer[0];
    
    memcpy(attestation_data, receive_buffer+1, PADDED_SIZE);

    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Convert uint8_t receive buffer to uint32_t transmit buffer
    uint32_t uint32_receive_buffer[PADDED_SIZE / sizeof(uint32_t)];
    memset(uint32_receive_buffer, 0, PADDED_SIZE / sizeof(uint32_t));
    //uint8_to_uint32(remaining_buffer, sizeof(remaining_buffer), uint32_receive_buffer, sizeof(uint32_receive_buffer)/sizeof(uint32_t));
    uint8_to_uint32(attestation_data, sizeof(attestation_data), uint32_receive_buffer, sizeof(uint32_receive_buffer)/sizeof(uint32_t));

    uint32_t decrypted[PADDED_SIZE / sizeof(uint32_t)]; // Decrypted data buffer
    memset(decrypted, 0, PADDED_SIZE/sizeof(uint32_t));

    // see pg.359 of MAX78000 User Guide for dummy encryption reason
    size_t ATTEST_SIZE = 224;
    uint32_t dummydata[ATTEST_SIZE / sizeof(uint32_t)];
    memset(dummydata, 0, ATTEST_SIZE / sizeof(uint32_t));
    uint32_t dummyreceive[len / sizeof(uint32_t)];
    int dummy_encrypt = AES_encrypt(0, MXC_AES_128BITS, dummydata, dummyreceive);

    int decrypt_success = AES_decrypt(0, MXC_AES_128BITS, MXC_AES_DECRYPT_INT_KEY, uint32_receive_buffer, decrypted);

    // convert uint32_t decrypted to uint8_t decrypted.
    size_t num_elements = sizeof(decrypted) / sizeof(uint32_t);
    size_t uint8_decrypted_size = num_elements * sizeof(uint32_t); // Size of the resulting uint8_t buffer
    uint8_t uint8_decrypted[uint8_decrypted_size];
    memset(uint8_decrypted, 0, uint8_decrypted_size);
    uint32_to_uint8(decrypted, num_elements, uint8_decrypted, sizeof(uint8_decrypted));

    uint8_t exact_decrypted[EXACT_SIZE];
    memcpy(exact_decrypted, uint8_decrypted, sizeof(exact_decrypted));
    
    exact_decrypted[EXACT_SIZE-1] = '\0';

    if (decrypt_success == 0) {
        // Print out attestation data
        print_info("C>0x%08x\n", component_id);
        print_info("%s", exact_decrypted);
        return SUCCESS_RETURN;
    }
    return ERROR_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // Example of how to utilize included simple_crypto.h
    #ifdef CRYPTO_EXAMPLE
    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char* data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    
    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext); 
    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results 
    uint8_t hash_out[HASH_SIZE];
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    print_hex_debug(hash_out, HASH_SIZE);
    
    // Decrypt the encrypted message and print out
    uint8_t decrypted[BLOCK_SIZE];
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    print_debug("Decrypted message: %s\r\n", decrypted);
    #endif

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[50];
    
    recv_input("Enter pin: ", buf);
    if(bcrypt_checkpw(buf, AP_PIN)==0){
        print_debug("Pin Accepted!\n");     
        
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50]; // Chang, check for timing
    recv_input("Enter token: ", buf);
    
    if(bcrypt_checkpw(buf, AP_TOKEN)==0){

        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);


    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                               sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                        component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
                component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    exchange_hash_key();
    char buf[50]; // check for timing changes

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    // Handle commands forever
    char buf[100];
    //bool first_hash_exchange = true;
    while (1) {
        recv_input("Enter Command: ", buf);
        if (!valid_device) {
            print_error("Invalid Device!");
            break;
        }
        // if (first_hash_exchange){
        //     if (strncmp(buf, "list", 4) != 0){
        //          exchange_hash_key();
        //     }
        //     first_hash_exchange = false;   
        // }
        // Execute requested command
        if (!strncmp(buf, "list", 4)) {
            scan_components();
        } else if (!strncmp(buf, "boot", 4)) {
            attempt_boot();
        } else if (!strncmp(buf, "replace", 7)) {
            attempt_replace();
        } else if (!strncmp(buf, "attest", 6)) {
            attempt_attest();
        } else {
            print_error("Unrecognized command");
        }
    }
    // Code never reaches here
    return 0;
}
