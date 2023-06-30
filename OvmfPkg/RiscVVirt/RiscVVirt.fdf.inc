## @file
#  Definitions of Flash definition file on RiscVVirt RISC-V platform
#
#  Copyright (c) 2021, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
#  Copyright (c) 2022, Ventana Micro Systems Inc. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
[Defines]
DEFINE BLOCK_SIZE                  = 0x1000

!if $(BUILD_STANDALONE_MM) == TRUE
DEFINE PFLASH0_BASE                = 0x80200000
DEFINE PFLASH1_BASE                = 0x82000000
!else
DEFINE PFLASH0_BASE                = 0x20000000
DEFINE PFLASH1_BASE                = 0x22000000
!endif

DEFINE CODE_BASE_ADDRESS           = $(PFLASH0_BASE)
DEFINE CODE_SIZE                   = 0x00800000
DEFINE CODE_BLOCKS                 = 0x800

DEFINE VARS_BASE_ADDRESS            = $(PFLASH1_BASE)
DEFINE VARS_SIZE                    = 0x000C0000
DEFINE VARS_BLOCK_SIZE              = 0x40000
DEFINE VARS_BLOCKS                  = 0x3

!if $(BUILD_STANDALONE_MM) == TRUE
DEFINE STANDALONE_MM_FW_BASE       = 0x80200000
DEFINE STANDALONE_MM_FW_SIZE       = 0x00100000
DEFINE STANDALONE_MM_FW_BLOCKS     = 0x100
!endif

#
# EFI Variable memory region.
# The total size of EFI Variable FD must include
# all of sub regions of EFI Variable
#
DEFINE VARS_OFFSET                   = 0x00000000
DEFINE VARS_LIVE_SIZE                = 0x00040000
DEFINE VARS_FTW_WORKING_OFFSET       = $(VARS_OFFSET) + $(VARS_LIVE_SIZE)
DEFINE VARS_FTW_WORKING_SIZE         = 0x00040000
DEFINE VARS_FTW_SPARE_OFFSET         = $(VARS_FTW_WORKING_OFFSET) + $(VARS_FTW_WORKING_SIZE)
DEFINE VARS_FTW_SPARE_SIZE           = 0x00040000

SET gUefiCpuPkgTokenSpaceGuid.PcdCpuCoreCrystalClockFrequency = 10000000
SET gUefiOvmfPkgTokenSpaceGuid.PcdOvmfSecPeiTempRamBase = 0x83FF0000
SET gUefiOvmfPkgTokenSpaceGuid.PcdOvmfSecPeiTempRamSize = 0x00010000

!if $(BUILD_STANDALONE_MM) == TRUE
# Put Mm FD just behind normal FW
SET gStandaloneMmPkgTokenSpaceGuid.PcdRiscVStandaloneMmFdBase = $(CODE_BASE_ADDRESS) + $(CODE_SIZE)
!endif