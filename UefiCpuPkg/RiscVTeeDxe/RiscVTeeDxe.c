/** @file
  RISC-V TEE DXE module implementation file.

  Copyright (c) 2023, Ventana Micro Systems Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "RiscVTeeDxe.h"

#define EXT_COVE_GUEST              0x434F5647
#define EXT_NACL                    0x4E41434C
#define EXT_PUT_CHAR                0x1
#define NACL_SET_SHMEM_FID          1
#define NACL_SCRATCH_BYTES          2048

typedef struct {
  /// Scratch space. The layout of this scratch space is defined by the particular function being
  /// invoked.
  ///
  /// For the `TvmCpuRun` function in the TEE-Host extension, the layout of this scratch space
  /// matches the `TsmShmemScratch` struct.
  UINT64 Scratch[NACL_SCRATCH_BYTES / 8];
  UINT64 _Reserved[240];
  /// Bitmap indicating which CSRs in `csrs` the host wishes to sync.
  ///
  /// Currently unused in the TEE-related extensions and will not be read or written by the TSM.
  UINT64 DirtyBitmap[16];
  /// Hypervisor and virtual-supervisor CSRs. The 12-bit CSR number is transformed into a 10-bit
  /// index by extracting bits `{csr[11:10], csr[8:0]}` since `csr[9:8]` is always 2'b10 for HS
  /// and VS CSRs.
  ///
  /// These CSRs may be updated by `TvmCpuRun` in the TEE-Host extension. See the documentation
  /// of `TvmCpuRun` for more detials.
  UINT64 Csrs[1024];
} NACL_SHMEM_T;

typedef struct {
  /// General purpose registers for a TVM guest.
  ///
  /// The TSM will always read or write the minimum number of registers in this set to complete
  /// the requested action, in order to avoid leaking information from the TVM.
  ///
  /// The TSM will write to these registers upon return from `TvmCpuRun` when:
  ///  - The vCPU takes a store guest page fault in an emulated MMIO region.
  ///  - The vCPU makes an ECALL that is to be forwarded to the host.
  ///
  /// The TSM will read from these registers when:
  ///  - The vCPU takes a load guest page fault in an emulated MMIO region.
    UINT64 GuestGprs[32];
    UINT64 _Reserved[224];
} TSM_SHMEM_SCRATCH;

#define NACL_CSR_IDX(CsrNum)      ((((CsrNum) & 0xc00) >> 2) | ((CsrNum) & 0xff))

STATIC NACL_SHMEM_T                 *ShmemPtr = NULL;
STATIC UINT64                       mTvmGuestId;
STATIC BOOLEAN                      mTvmRunBlock;
STATIC UINT64                       mGuestSharedMemoryBase;
STATIC UINT64                       mGuestSharedMemorySize;
STATIC UINT64                       *mHostSharedMemoryBase = NULL;
STATIC EFI_TIMER_ARCH_PROTOCOL      *gTimerAp = NULL;

STATIC
BOOLEAN
RiscVTeeMmioRegionCheck (IN UINT64 Address, IN UINT64 Len)
{
  /* Check if Mmio request from TVM valid */
  return TRUE;
}

EFI_STATUS
RiscVTeeHandleGuestRequest (VOID)
{
  TSM_SHMEM_SCRATCH       *TsmScratch;
  UINT64                  ARegs[8];
  EFI_STATUS              Status = EFI_SUCCESS;
  SBI_RET                 Ret;

  TsmScratch = (TSM_SHMEM_SCRATCH *)(ShmemPtr->Scratch);
  MmioReadBuffer64 ((UINT64)(&TsmScratch->GuestGprs[10]), 8 * sizeof(UINT64), ARegs);
  switch (ARegs[6]) {
  case 0://AddMmioRegion
   DEBUG ((DEBUG_VERBOSE, "%a: Add MMIO region %llX, size: %llX\n", __func__,
              ARegs[0], ARegs[1]));
    if (RiscVTeeMmioRegionCheck (ARegs[0], ARegs[1]) != TRUE) {
      Status = EFI_ACCESS_DENIED;
    }
    break;
  case 1://RemoveMmioRegion
    break;
  case 2://AddSharedMemory
    DEBUG ((DEBUG_VERBOSE, "%a: Add shared region %llX, size: %llX\n", __func__,
              ARegs[0], ARegs[1]));
    mGuestSharedMemoryBase = ARegs[0];
    mGuestSharedMemorySize = ARegs[1];
    if (mHostSharedMemoryBase) {
      DEBUG ((DEBUG_ERROR, "%a: The base %llX already shared => %p\n", __func__,
              mGuestSharedMemoryBase, mHostSharedMemoryBase));
      Status = EFI_ALREADY_STARTED;
      break;
    }
    if (mGuestSharedMemorySize > MM_VM_RAM_MM_SHARED_BUF_SIZE) {
      DEBUG ((DEBUG_ERROR, "%a: Size too big %llX, max: %llX\n", __func__,
              mGuestSharedMemorySize, MM_VM_RAM_MM_SHARED_BUF_SIZE));
      break;
    }
    // Tell guest page sharing has been accepted
    ARegs[0] = 0;
    MmioWriteBuffer64((UINT64)(&TsmScratch->GuestGprs[10]), 1 * sizeof(UINT64), ARegs);
    break;
  case 3://UnshareMemory
    // Not expecting guest to un-share memory
    ASSERT (FALSE);
    break;
  default:
    DEBUG ((DEBUG_ERROR, "%a: Unhandled guest request: %llX\n", __func__,
             ARegs[6]));
    Status = EFI_NOT_FOUND;
    break;
  }
  if (mTvmRunBlock) {
    Ret = SbiTeeHostRunTvmVcpu (mTvmGuestId, RISCV_TEE_VCPU_ID);
    ASSERT (Ret.Error == SBI_TEE_SUCCESS);
    mTvmRunBlock = Ret.Value;
    SbiTeeHostTvmFence (mTvmGuestId);
  }

  return Status;
}

STATIC
EFI_STATUS
RiscVTeeHandleMmioAccess (IN UINT64 FaultAddr)
{
  TSM_SHMEM_SCRATCH     *TsmScratch;
  UINT32                Instruction;
  UINT64                Val;
  UINTN                 Size;
  BOOLEAN               Write = 0;

  TsmScratch = (TSM_SHMEM_SCRATCH *)(ShmemPtr->Scratch);
  Instruction = MmioRead32 ((UINT64)(&ShmemPtr->Csrs[NACL_CSR_IDX(CSR_HTINST)]));

  switch (Instruction & 0b11) {
  case 0b11:
    switch ((Instruction >> 2) & 0b11111) {
    case 0b00000:
      Write = 0;
      break;
    case 0b01000:
      /* Store instruction */
      Write = 1;
      break;
    default:
      return EFI_INVALID_PARAMETER;
    }
    break;
  default:
    return EFI_INVALID_PARAMETER;
  }
  switch ((Instruction >> 12) & 0b111) {
  case 0b000:
  case 0b100:
    /* Lb/Lbu/Sb */
    Size = 1;
    break;
  case 0b001:
  case 0b101:
    /* Lh/Lhu/Sh */
    Size = 2;
    break;
  case 0b010:
  case 0b110:
    /* Lw/Lwu/Sw */
    Size = 4;
    break;
  case 0b011:
    /* Ld/sd */
    Size = 8;
    break;
  default:
    return EFI_INVALID_PARAMETER;
  }

  /* Make sure the range not excess MMIO region */
  if (!RiscVTeeMmioRegionCheck (FaultAddr,  Size)) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Write) {
    switch (Size) {
    case 1:
      Val = MmioRead8 (FaultAddr);
      break;
    case 2:
      Val = MmioRead16 (FaultAddr);
      break;
    case 4:
      Val = MmioRead32 (FaultAddr);
      break;
    case 8:
      Val = MmioRead64 (FaultAddr);
      break;
    default:
      return EFI_INVALID_PARAMETER;
    }
    MmioWrite64 ((UINT64)(&TsmScratch->GuestGprs[10]), Val);
  } else {
    Val = MmioRead64 ((UINT64)(&TsmScratch->GuestGprs[10]));
    switch (Size) {
    case 1:
      Val = MmioWrite8 (FaultAddr, Val);
      break;
    case 2:
      Val = MmioWrite16 (FaultAddr, Val);
      break;
    case 4:
      Val = MmioWrite32 (FaultAddr, Val);
      break;
    case 8:
      Val = MmioWrite64 (FaultAddr, Val);
      break;
    default:
      return EFI_INVALID_PARAMETER;
    }
  }

  return EFI_SUCCESS;
}

/*
  Handle any requests from TVM

  return
    EFI_SUCCESS - Processed requests succesfully
    EFI_INVALID_PARAMETER - No requests from TVM
 */
STATIC
EFI_STATUS
RiscVTeeException (
  IN CONST  EFI_EXCEPTION_TYPE  InterruptType
  )
{
  TSM_SHMEM_SCRATCH           *TsmScratch;
  EFI_STATUS                  Status = EFI_INVALID_PARAMETER;
  UINT64                      FaultAddr;
  UINT64                      ARegs[8];
  SBI_RET                     Ret;

  if (InterruptType == EXCEPT_RISCV_ENV_CALL_FROM_VS_MODE) {
    // Info stored in A0->A7
    TsmScratch = (TSM_SHMEM_SCRATCH *)(ShmemPtr->Scratch);
    MmioReadBuffer64 ((UINT64)(&TsmScratch->GuestGprs[10]), 8 * sizeof(UINT64), ARegs);
    switch (ARegs[7]) {
    case EXT_COVE_GUEST:
      Status = RiscVTeeHandleGuestRequest ();
      break;
    case EXT_PUT_CHAR:
      Ret = SbiCall (ARegs[7], 0, 1, ARegs[0]);
      ASSERT (Ret.Error == SBI_SUCCESS);
      ARegs[0] = 0;
      MmioWriteBuffer64((UINT64)(&TsmScratch->GuestGprs[10]), 1 * sizeof(UINT64), ARegs);
      Status = EFI_SUCCESS;
      break;
    default:
      DEBUG ((DEBUG_ERROR, "%a: Unhandled ecall from vs mode : %X\n", __func__,
              ARegs[7]));
      break;
    }
  }

  if (InterruptType == EXCEPT_RISCV_LOAD_GUEST_PAGE_FAULT ||
      InterruptType == EXCEPT_RISCV_STORE_GUEST_PAGE_FAULT) {
    FaultAddr = (MmioRead64 ((UINT64)(&ShmemPtr->Csrs[NACL_CSR_IDX(CSR_HTVAL)])) << 2) | (RiscVGetStvalRegister () & 0x3);
    if (FaultAddr >= (MM_VM_RAM_BASE + MM_VM_RAM_MM_SHARED_BUF_OFFSET) &&
      FaultAddr < (MM_VM_RAM_BASE + MM_VM_RAM_MM_SHARED_BUF_OFFSET + MM_VM_RAM_MM_SHARED_BUF_SIZE)) {
      // Allocate shared memory
      if (!mHostSharedMemoryBase) {
        mHostSharedMemoryBase  = (UINT64 *)AllocateRuntimePages (MM_VM_RAM_MM_SHARED_BUF_SIZE / SIZE_4KB);
        ASSERT (mHostSharedMemoryBase);
        SetMem ((VOID *)mHostSharedMemoryBase, MM_VM_RAM_MM_SHARED_BUF_SIZE, 0);
        Ret = SbiTeeHostAddTvmSharedPages (mTvmGuestId,
                                          (UINT64)mHostSharedMemoryBase, TSM_PAGE_4K,
                                          MM_VM_RAM_MM_SHARED_BUF_SIZE / SIZE_4KB,
                                          MM_VM_RAM_BASE + MM_VM_RAM_MM_SHARED_BUF_OFFSET);
        ASSERT (Ret.Error == SBI_SUCCESS);
      }
      Status = EFI_SUCCESS;
    } else if (RiscVTeeMmioRegionCheck (FaultAddr, 0)) {
      Status = RiscVTeeHandleMmioAccess (FaultAddr);
    } else {
      Status = EFI_INVALID_PARAMETER;
    }
  }

  if (InterruptType == EXCEPT_RISCV_VIRTUAL_INSTRUCTION) {
    // Only wfi should be received. Expecting host pause TVM
    return EFI_INVALID_PARAMETER;
  }

  return Status;
}

EFIAPI
EFI_STATUS RiscVTriggerMM (VOID)
{
  UINT64      TimerPeriod;
  EFI_STATUS  Status;
  SBI_RET     Ret;

  // Make sure timer disabled, otherwise TVM be interrupted event host interrupt disabled
  if (gTimerAp != NULL) {
    ASSERT_EFI_ERROR (gTimerAp->GetTimerPeriod (gTimerAp, &TimerPeriod));
    if (TimerPeriod != 0) {
      ASSERT_EFI_ERROR (gTimerAp->SetTimerPeriod (gTimerAp, 0));
    }
  }

  Status = EFI_SUCCESS;
  do {
    Ret = SbiTeeHostRunTvmVcpu (mTvmGuestId, RISCV_TEE_VCPU_ID);
    ASSERT(Ret.Error == SBI_TEE_SUCCESS);
    if (Ret.Error != SBI_TEE_SUCCESS) {
      Status = EFI_DEVICE_ERROR;
    }
    mTvmRunBlock = Ret.Value;
  } while (RiscVTeeException (RiscVGetScauseRegister ()) != EFI_INVALID_PARAMETER);

  if (TimerPeriod != 0) {
    ASSERT_EFI_ERROR (gTimerAp->SetTimerPeriod (gTimerAp, TimerPeriod));
  }

  return Status;
}

/**
  The user Entry Point for module RiscVTeeDxe.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
RiscVTeeDxeInitialize (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS        Status;
  SBI_RET           Ret;

  Status = gBS->LocateProtocol (&gEfiTimerArchProtocolGuid, NULL, (VOID **)&gTimerAp);
  if (EFI_ERROR (Status)) {
    gTimerAp = NULL;
  }

  Status = StandaloneMmInitialization (&mTvmGuestId);
  if (EFI_ERROR (Status)) {
    DEBUG  ((DEBUG_ERROR, "%a: Failed to initialize MM :%r", __func__, Status));
    return Status;
  }

  // Register Shmem
  ShmemPtr = (NACL_SHMEM_T *)AllocateAlignedPages ((sizeof (NACL_SHMEM_T) + SIZE_4KB - 1) / SIZE_4KB, SIZE_4KB);
  ASSERT (ShmemPtr);
  Ret = SbiCall (EXT_NACL, NACL_SET_SHMEM_FID, 1, (UINT64)ShmemPtr);
  ASSERT (Ret.Error == SBI_SUCCESS);

  // Trigger MM to intialize its resource
  Status = RiscVTriggerMM ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Register MmCommunicate2 protocol
  ASSERT (mHostSharedMemoryBase);
  Status = RiscVTeeMmCommunication2Initialize (mHostSharedMemoryBase, MM_VM_RAM_MM_SHARED_BUF_SIZE);
  ASSERT_EFI_ERROR (Status);

  return Status;
}
