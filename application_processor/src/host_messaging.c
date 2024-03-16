/**
 * @file host_messaging.c
 * @author Frederich Stine
 * @brief eCTF Host Messaging Implementation 
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "host_messaging.h"

// Print a message through USB UART and then receive a line over USB UART
// void recv_input(const char *msg, char *buf) {
//     print_debug(msg);
//     fflush(0);
//     print_ack();
//     fgets(buf, 100, stdin); //CHANGE TO FGETS
// }

//stuff i am trying:

void recv_input(const char *msg, char *buf) {
    print_debug(msg);
    fflush(0);
    print_ack();

    if (fgets(buf, 17, stdin) != NULL) {
        size_t len = strlen(buf);
        if(len > 0 && buf[len-1] == '\n') {
            buf[len-1] = '\0';
        }
    } else {
        buf[0] = '\0';

    }

}


// void recv_input(const char *msg, char *buf) {
//     print_debug(msg);
//     fflush(0);
//     print_ack();
//     if (fgets(buf, 7, stdin) == NULL) {
//         buf[0] = '\0';
//     } else {
//         char* newline = strchr(buf, '\n');
//         if (newline) {
//         *newline = '\0';
//     }
//     }
//     puts("");
// }

// // Print a message through USB UART and then receive a line over USB UART
// void recv_input_50(const char *msg, char *buf) {
//     print_debug(msg);
//     fflush(0);
//     print_ack();
//     fgets(buf, 50, stdin); //DOUBLE CHECK PRACTICALITY OF 8
//     puts("");
// }

// Prints a buffer of bytes as a hex string
void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}
