# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
CRYPTO_EXAMPLE=0

# Enable Crypto Example
#CRYPTO_EXAMPLE=1

TARGET_UC:=$(shell echo $(TARGET) | tr a-z A-Z)
TARGET_LC:=$(shell echo $(TARGET) | tr A-Z a-z)

# Specify the library variant.
ifeq "$(MFLOAT_FLAGS)" "hardfp"
LIBRARY_VARIANT=hardfp
else
ifeq "$(MFLOAT_FLAGS)" "hard"
LIBRARY_VARIANT=hardfp
else
LIBRARY_VARIANT=softfp
endif
endif

# Specify the build directory if not defined by the project
ifeq "$(BUILD_DIR)" ""
ifeq "$(RISCV_CORE)" ""
PERIPH_DRIVER_BUILD_DIR=${PERIPH_DRIVER_DIR}/bin/$(TARGET_UC)/$(LIBRARY_VARIANT)
else
PERIPH_DRIVER_BUILD_DIR=${PERIPH_DRIVER_DIR}/bin/$(TARGET_UC)/$(LIBRARY_VARIANT)_riscv
endif
else
PERIPH_DRIVER_BUILD_DIR=$(BUILD_DIR)/PeriphDriver
endif

# Export other variables needed by the peripheral driver makefile
export TARGET
export COMPILER
export TARGET_MAKEFILE
export PROJ_CFLAGS
export PROJ_LDFLAGS
export MXC_OPTIMIZE_CFLAGS
export DUAL_CORE
export RISCV_CORE

IPATH += ${PERIPH_DRIVER_INCLUDE_DIR}
ifeq "$(LIBRARY_VARIANT)" ""
PERIPH_DRIVER_LIB := libPeriphDriver.a
else
PERIPH_DRIVER_LIB := libPeriphDriver_$(LIBRARY_VARIANT).a
endif
# export PERIPH_DRIVER_DIR
export PERIPH_DRIVER_LIB
export PERIPH_DRIVER_BUILD_DIR

# Add to library list
LIBS += ${PERIPH_DRIVER_BUILD_DIR}/${PERIPH_DRIVER_LIB}
# Add rule to build the Driver Library
${PERIPH_DRIVER_BUILD_DIR}/${PERIPH_DRIVER_LIB}: ${PERIPH_DRIVER_C_FILES} ${PERIPH_DRIVER_A_FILES} ${PERIPH_DRIVER_H_FILES}
	$(MAKE) -f ${PERIPH_DRIVER_DIR}/libPeriphDriver.mk  lib BUILD_DIR=${PERIPH_DRIVER_BUILD_DIR} 

clean.periph:
	@rm -rf ${PERIPH_DRIVER_BUILD_DIR}/*