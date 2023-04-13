/** @file
  Copyright (c) 2023, Ventana Micro Systems Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "RiscVTeeDxe.h"

.data
.align 3
.section .text

//
// Get scause trap value register.
//
ASM_FUNC (RiscVGetScauseRegister)
    csrr a0, CSR_SCAUSE
    ret

//
// Get stval trap value register.
//
ASM_FUNC (RiscVGetStvalRegister)
    csrr a0, CSR_STVAL
    ret
