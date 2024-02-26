/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "simple_flash.h"
#include "host_messaging.h"
#include "dictionary.h"
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
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

// Hash Digest
#define SHA256_DIGEST_LENGTH 32
#define MAX_KEY_LENGTH 256

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode; // 1 byte
    uint8_t authkey[HASH_SIZE]; // 16 bytes
    uint32_t random_number; //4 bytes for the RNG
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id; // 4 byte
    uint8_t authkey[HASH_SIZE]; // 16 bytes
    //uint8_t random_number[4]; //4 bytes for the RNG
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id; // 4 byte
    uint8_t authkey[HASH_SIZE]; // 16 bytes
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic; // 4 bytes
    uint32_t component_cnt; // 4 bytes
    uint32_t component_ids[32]; // 4 bytes
} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;


/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;
Dictionary dict;

/********************************* REFERENCE FLAG **********************************/
// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// NOTE: you're not allowed to do this in your code
// Remove this in your design
typedef uint32_t aErjfkdfru;const aErjfkdfru aseiFuengleR[]={0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x12614f7,0x1ffe4b6,0x11a38bb,0x1ffe4b6,0x12614f7,0x1ffe4b6,0x12220e3,0x3098ac,0x1ffe4b6,0x2ca498,0x11a38bb,0xe6d3b7,0x1ffe4b6,0x127bc,0x3098ac,0x11a38bb,0x1d073c6,0x51bd0,0x127bc,0x2e590b1,0x1cc7fb2,0x1d073c6,0xeac7cb,0x51bd0,0x2ba13d5,0x2b22bad,0x2179d2e,0};const aErjfkdfru djFIehjkklIH[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x38ec6f2,0x138e798,0x23bcfda,0x138e798,0x38ec6f2,0x138e798,0x31dc9ea,0x2cdbb14,0x138e798,0x25cbe0c,0x23bcfda,0x199a72,0x138e798,0x11c82b4,0x2cdbb14,0x23bcfda,0x3225338,0x18d7fbc,0x11c82b4,0x35ff56,0x2b15630,0x3225338,0x8a977a,0x18d7fbc,0x29067fe,0x1ae6dee,0x4431c8,0};typedef int skerufjp;skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe){skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}


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
 * @brief GenerateAndUseRandomID
 * 
 * @param command: command_message*, pointer to a command_message struct
 * 
 * Attach hashed authentication key to given command struct object. Assign command->authkey value of hash.  
*/
void attach_key(command_message* command){
    char* key = KEY;
    uint8_t hash_out[HASH_SIZE];
    hash(key, HASH_SIZE, hash_out);
    memcpy(command->authkey, hash_out, HASH_SIZE);
    
}

void attach_random_num(command_message* command){
    command->random_number = GenerateAndUseRandomID();
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
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
    hash(data_key_randnum, data_key_randnum_len, hash_out);
    free(data_key_randnum);

    // Add security attributes to packet
    memcpy(temp_buffer + hash_position, hash_out, HASH_SIZE); // add authenication hash
    temp_buffer[data_len_position] = len; // add data length
    memcpy(temp_buffer + random_number_position, &random_number, sizeof(uint32_t)); // add random number

    // Update random number assignment for component
    addOrUpdate(&dict, address, random_number);

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
    size_t MAX_PACKET_SIZE = MAX_I2C_MESSAGE_LEN - 1;

    uint8_t len = poll_and_receive_packet(address, buffer); 

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
    hash(data_key_randnum, data_key_randnum_len, check_hash);
    free(data_key_randnum);

    // Check hash for integrity and authenticity of the message
    if(!hash_equal(received_hash, check_hash) || random_number != getValue(&dict, address)){
        print_error("Could not validate Component\n");
        return ERROR_RETURN;
    }

    // Extract the original message
    // uint8_t original_message[data_len + 1]; // Add one for the null terminator
    // memcpy(original_message, buffer, data_len);
    // original_message[data_len] = '\0'; // Null-terminate the string

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
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    // Initialize board link interface
    board_link_init();
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
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {

    size_t PACKET_SIZE = HASH_SIZE + sizeof(uint8_t) + sizeof(uint32_t);

    // Send message
    int result = send_packet(addr, PACKET_SIZE, transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

int validate_components() {
    print_debug("In Validate Components");
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    //uint8_t rngValue[4];

     // Generate RNG value once for all components
    // GenerateAndUseRandomID(rngValue, sizeof(rngValue));
    // print_debug("Generated RNG for validation: ");
    // print_hex_debug(rngValue, sizeof(rngValue));

    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;

       // Attach authentication hash
        attach_key(command);
        //attach_random_num(command);

        uint32_t test_random_num = 12345;
        command->random_number = test_random_num;
        print_debug("Random number sent: %u", command->random_number);

        //print_hex_debug(command->random_number, sizeof(command->random_number));

        //memcpy(command->random_number, rngValue, sizeof(rngValue));

        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }
        validate_message* validate = (validate_message*) receive_buffer;

        // Validate received authentication hash
        if(!hash_equal(command->authkey, validate->authkey)){
            //if(!hash_equal(command->authkey, validate->authkey) || !memcmp(command->random_number, validate->random_number, sizeof(rngValue))){
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int scan_components() {
    print_debug("Scan Components");
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
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
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;

        // Attach authentication hash
        attach_key(command);
        //attach_random_num(command);
        uint32_t test_random_num = 12345;
        command->random_number = test_random_num;
        

        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_debug("Random number sent: %u", command->random_number);
           //print_hex_debug(command->random_number, sizeof(command->random_number));
            // Validate received authentication hash
            if(!hash_equal(command->authkey, scan->authkey)){
                return ERROR_RETURN;
            }
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;

        // Attach authentication hash
        attach_key(command);

        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Validate received authentication hash
        if (!hash_equal(command->authkey, &receive_buffer[len-HASH_SIZE])){
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Attach authentication hash
    attach_key(command);

    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Validate received authentication hash
    if (!hash_equal(command->authkey, &receive_buffer[len-HASH_SIZE])){
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    clock_t start_time, end_time;
    //Starts the clock
    start_time = clock();

    char buf[50];
    print_debug("Validate pin called!");
    recv_input("Enter pin: ", buf);
    print_debug("Verifying PIN...\n");
    if(bcrypt_checkpw(buf, AP_PIN)==0){
        print_debug("Pin Accepted!\n");
        // Ends the clock
        end_time = clock();
        
        //Calculates the time it took to verify the pin
        double time_taken = ((double)end_time - start_time)/CLOCKS_PER_SEC;
        print_debug("Time taken to verify pin: %f\n", time_taken);
        
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    print_debug("Verifying Token...\n");

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
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

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
    print_debug("Attempt Attest called!");
    char buf[50];

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
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf);
        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            print_debug("attest command called !");
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }
    // Code never reaches here
    return 0;
}
