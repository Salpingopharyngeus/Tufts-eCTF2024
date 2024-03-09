/**
 * @file "board_link.c"
 * @author Frederich Stine
 * @brief High Level API for I2C Controller Communications Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2SUCCESS_RETURN23
 * Embedded System CTF (eCTF). This code is being provided only for educational
 * purposes for the 2SUCCESS_RETURN23 MITRE eCTF competition, and may not meet
 * MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "mxc_device.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <tmr.h>
#include <tmr_regs.h>

#include "board_link.h"
#include "host_messaging.h"
#include "mxc_delay.h"
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

// Timer to be used
mxc_tmr_regs_t *timer = MXC_TMR0; // Replace with your specific timer
// Starting ticks
static uint32_t startTime = 0;
// Function to start the timer, storing the start time
void startTimer() {
    // Assuming MXC_TMR_GetTicks() is a function that retrieves the current
    // timer tick count
    startTime = MXC_TMR_GetTicks(timer);
}

// Function to check if 3 seconds have passed since the timer started
bool hasThreeSecondsPassed() {
    uint32_t currentTime;
    uint32_t timeElapsed;
    mxc_tmr_unit_t units;

    // Assuming MXC_TMR_GetTime() to calculate the time elapsed since startTime
    // in seconds
    MXC_TMR_GetTime(timer, startTime, &currentTime, &units);

    // Check if the units are in seconds, then check if 3 seconds have elapsed
    if (units == MXC_TMR_UNIT_SEC) {
        timeElapsed = currentTime - startTime;
        if (timeElapsed >= 3) {
            // Optionally, reset startTime to check for another 3 second
            // interval
            printf("REBOOT");
            return true;
        }
    }

    return false;
}

/******************************** FUNCTION DEFINITIONS
 * ********************************/
/**
 * @brief Initialize the board link connection
 *
 * Initiailize the underlying i2c simple interface
 */
void board_link_init(void) { i2c_simple_controller_init(); }

/**
 * @brief Convert 4-byte component ID to I2C address
 *
 * @param component_id: uint32_t, component_id to convert
 *
 * @return i2c_addr_t, i2c address
 */
i2c_addr_t component_id_to_i2c_addr(uint32_t component_id) {
    return (uint8_t)component_id & COMPONENT_ADDR_MASK;
}

/**
 * @brief Send an arbitrary packet over I2C
 *
 * @param address: i2c_addr_t, i2c address
 * @param len: uint8_t, length of the packet
 * @param packet: uint8_t*, pointer to packet to be sent
 *
 * @return status: SUCCESS_RETURN if success, ERROR_RETURN if error
 *
 * Function sends an arbitrary packet over i2c to a specified component
 */
int send_packet(i2c_addr_t address, uint8_t len, uint8_t *packet) {
    int result;
    result = i2c_simple_write_receive_len(address, len);
    if (result < SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    result = i2c_simple_write_data_generic(address, RECEIVE, len, packet);
    if (result < SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    result = i2c_simple_write_receive_done(address, true);
    if (result < SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

/**
 * @brief Poll a component and receive a packet
 *
 * @param address: i2c_addr_t, i2c address
 * @param packet: uint8_t*, pointer to a buffer where a packet will be received
 *
 * @return int: size of data received, ERROR_RETURN if error
 */
int poll_and_receive_packet(i2c_addr_t address, uint8_t *packet) {
    int result = SUCCESS_RETURN;

    startTimer();

    while (true) {
        result = i2c_simple_read_transmit_done(address);

        if (result < SUCCESS_RETURN) {
            if (hasThreeSecondsPassed()) {
                printf("exited");
            }
            return ERROR_RETURN;
        } else if (result == SUCCESS_RETURN) {
            if (hasThreeSecondsPassed()) {
                printf("exited");
            }
            break;
        }
        MXC_Delay(50);
    }
    int len = i2c_simple_read_transmit_len(address);
    if (len < SUCCESS_RETURN) {
        if (hasThreeSecondsPassed()) {
            printf("exited");
        }
        return ERROR_RETURN;
    }
    result =
        i2c_simple_read_data_generic(address, TRANSMIT, (uint8_t)len, packet);
    if (result < SUCCESS_RETURN) {
        if (hasThreeSecondsPassed()) {
            printf("exited");
        }
        return ERROR_RETURN;
    }
    result = i2c_simple_write_transmit_done(address, true);
    if (result < SUCCESS_RETURN) {
        if (hasThreeSecondsPassed()) {
            printf("exited");
        }
        return ERROR_RETURN;
    }
    if (hasThreeSecondsPassed()) {
        printf("exited");
    }
    return len;
}
