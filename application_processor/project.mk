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

VPATH+= /src/crypt-blowfish

# Custom rule for compiling crypt_blowfish.c
application_processor/crypt_blowfish/crypt_blowfish.o: application_processor/src/crypt_blowfish/crypt_blowfish.c application_processor/crypt_blowfish/crypt_blowfish.h
	$(CC) $(CFLAGS) $(foreach dir,$(IPATH),-I$(dir)) -c $< -o $@
crypt_blowfish.o: application_processor/crypt_blowfish/crypt_blowfish.h

# Add the source files of crypt_blowfish directly for compilation
SRCS += /crypt-blowfish/crypt_blowfish.c \
		/crypt-blowfish/x86.S \
		/crypt-blowfish/crypt_gensalt.c \
		/crypt-blowfish/wrapper.c

# Specify the include directory for the crypt_blowfish headers
IPATH += /crypt-blowfish

# Add any necessary compiler flags, mimicking those from the crypt_blowfish Makefile
CFLAGS += -W -Wall -O2 -fomit-frame-pointer -funroll-loops

# Add the library path for the linker (if the library is a compiled binary)
# Assuming the library file is named libcrypt_blowfish.a and located in the same directory
LIBRARY_PATHS += /crypt-blowfish

# Add the library to be linked
# Note: When specifying the library, you typically omit the 'lib' prefix and '.a' (or '.so') suffix
LIBRARIES += crypt_blowfish

# If the library path needs to be explicitly included during the link stage, use LDFLAGS
LDFLAGS += -L/crypt-blowfish

# Inform the linker to use the crypt_blowfish library
LDFLAGS += -lcrypt_blowfish

# Modifies the build process to hash the PIN and TOKEN in the ectf_params.h file before the build process begins. 
# This is done by adding a custom target to the Makefile that runs a Python script to hash the PIN and TOKEN values in the ectf_params.h file. 
# The custom target is then added to the pre-build process to ensure that it runs before the build process begins.

# Define the path to ectf_params.h
ECTF_PARAMS_PATH := inc/ectf_params.h

# Custom target for processing ectf_params.h
process-ectf-params: $(ECTF_PARAMS_PATH)
	@echo "Running Python script to hash PIN and TOKEN in $(ECTF_PARAMS_PATH)..."
	@python3 src/bcrypt_pin.py $(ECTF_PARAMS_PATH)

# Ensure the custom script runs before the build process
pre-build: process-ectf-params

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