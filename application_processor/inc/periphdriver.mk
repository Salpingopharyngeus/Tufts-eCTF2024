################################################################################
 # Copyright (C) 2016 Maxim Integrated Products, Inc., All Rights Reserved.
 #
 # Permission is hereby granted, free of charge, to any person obtaining a
 # copy of this software and associated documentation files (the "Software"),
 # to deal in the Software without restriction, including without limitation
 # the rights to use, copy, modify, merge, publish, distribute, sublicense,
 # and/or sell copies of the Software, and to permit persons to whom the
 # Software is furnished to do so, subject to the following conditions:
 #
 # The above copyright notice and this permission notice shall be included
 # in all copies or substantial portions of the Software.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 # IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 # OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 # ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 # OTHER DEALINGS IN THE SOFTWARE.
 #
 # Except as contained in this notice, the name of Maxim Integrated
 # Products, Inc. shall not be used except as stated in the Maxim Integrated
 # Products, Inc. Branding Policy.
 #
 # The mere transfer of this software does not imply any licenses
 # of trade secrets, proprietary technology, copyrights, patents,
 # trademarks, maskwork rights, or any other form of intellectual
 # property whatsoever. Maxim Integrated Products, Inc. retains all
 # ownership rights.
 #
 # $Date: 2018-12-18 15:37:22 -0600 (Tue, 18 Dec 2018) $ 
 # $Revision: 40072 $
 #
 ###############################################################################

################################################################################
# This file can be included in a project makefile to build the library for the 
# project.
################################################################################

ifeq "$(PERIPH_DRIVER_DIR)" ""
$(error "PERIPH_DRIVER_DIR must be specified")
endif

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

include ${PERIPH_DRIVER_DIR}/$(TARGET_LC)_files.mk
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