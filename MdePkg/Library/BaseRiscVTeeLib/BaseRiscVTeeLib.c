/** @file
  RISC-V TEE library implementation.

  Copyright (c) 2023, Ventana Micro System Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseRiscVTeeLib.h>

/**
  The constructor function to initialize all static structures.

  @retval EFI_SUCCESS   The destructor completed successfully.
  @retval Other value   The destructor did not complete successfully.

**/
RETURN_STATUS
EFIAPI
BaseRiscVTeeLibConstructor (VOID)
{
  return EFI_SUCCESS;
}
