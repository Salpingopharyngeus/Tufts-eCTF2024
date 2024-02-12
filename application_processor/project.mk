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

# Add the source files of crypt_blowfish directly for compilation
SRCS += application_processor/crypt-blowfish/crypt_blowfish.c \
        application_processor/crypt-blowfish/x86.S \
        application_processor/crypt-blowfish/crypt_gensalt.c \
        application_processor/crypt-blowfish/wrapper.c

# Specify the include directory for the crypt_blowfish headers
IPATH += application_processor/crypt-blowfish

# Add any necessary compiler flags, mimicking those from the crypt_blowfish Makefile
CFLAGS += -W -Wall -O2 -fomit-frame-pointer -funroll-loops

# Add the library path for the linker (if the library is a compiled binary)
# Assuming the library file is named libcrypt_blowfish.a and located in the same directory
LIBRARY_PATHS += application_processor/crypt-blowfish

# Add the library to be linked
# Note: When specifying the library, you typically omit the 'lib' prefix and '.a' (or '.so') suffix
LIBRARIES += crypt_blowfish

# If the library path needs to be explicitly included during the link stage, use LDFLAGS
LDFLAGS += -Lapplication_processor/crypt-blowfish

# Inform the linker to use the crypt_blowfish library
LDFLAGS += -lcrypt_blowfish


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
