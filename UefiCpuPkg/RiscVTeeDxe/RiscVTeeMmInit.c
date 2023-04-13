/** @file
Load and start StandaloneMm image

Copyright (c) 2023, Ventana Micro Systems Inc. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Pi/PiMultiPhase.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseRiscVSbiLib.h>
#include <Library/BaseRiscVTeeLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include "RiscVTeeDxe.h"

#define CPU_INFO_FLAG_PRIMARY_CPU   0x00000001
#define BOOT_PAYLOAD_VERSION        1
#define EFI_PARAM_ATTR_APTEE        1

typedef struct {
  UINT8     Type;    /* type of the structure */
  UINT8     Version; /* version of this structure */
  UINT16    Size;    /* size of this structure in bytes */
  UINT32    Attr;    /* attributes */
} EFI_PARAM_HEADER;

typedef struct {
  UINT32    ProcessorId;
  UINT32    Package;
  UINT32    Core;
  UINT32    Flags;
} EFI_RISCV_MM_CPU_INFO;

typedef struct {
  EFI_PARAM_HEADER                 Header;
  UINT64                           MmMemBase;
  UINT64                           MmMemLimit;
  UINT64                           MmImageBase;
  UINT64                           MmStackBase;
  UINT64                           MmHeapBase;
  UINT64                           MmNsCommBufBase;
  UINT64                           MmSharedBufBase;
  UINT64                           MmImageSize;
  UINT64                           MmPcpuStackSize;
  UINT64                           MmHeapSize;
  UINT64                           MmNsCommBufSize;
  UINT64                           MmSharedBufSize;
  UINT32                           NumMmMemRegions;
  UINT32                           NumCpus;
  EFI_RISCV_MM_CPU_INFO            CpuInfo;
} EFI_RISCV_MM_BOOT_INFO;

#define ENTRIES_PER_PAGE                  512

STATIC
UINT64
CalculateMaxPtePages (IN UINT64 TotalSize)
{
  // Assuming SV48 mode only
  UINTN NumL1, NumL2, NumL3, NumL4;

  NumL1 = (TotalSize / SIZE_4KB) / ENTRIES_PER_PAGE + 1;
  NumL2 = NumL1 / ENTRIES_PER_PAGE + 1;
  NumL3 = NumL2 / ENTRIES_PER_PAGE + 1;
  NumL4 = 1;

  return NumL1 + NumL2 + NumL3 + NumL4;
}

STATIC
EFI_STATUS
ConvertToConfidentialMemory (IN UINT64 BaseAddr, IN UINT32 NumPage)
{
  SBI_RET   Ret;

  Ret = SbiTeeHostConvertPages (BaseAddr, NumPage);
  if (Ret.Error != SBI_TEE_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "%a: Could not convert non-confidential pages: 0x%llX-0x%llX, ret:%d\n",
            __func__, BaseAddr, BaseAddr + NumPage * SIZE_4KB, Ret.Error));
    return EFI_DEVICE_ERROR;
  }
  SbiTeeHostGlobalFence ();

  return EFI_SUCCESS;
}

STATIC
VOID
CreateMmBootInfo (
  IN EFI_RISCV_MM_BOOT_INFO *BootInfo,
  IN UINT64                 MmVmMemBase,
  IN UINT64                 MmVmMemSize
  )
{
  EFI_RISCV_MM_CPU_INFO *CpuInfo;

  ASSERT (BootInfo);
  BootInfo->Header.Version = BOOT_PAYLOAD_VERSION;
  BootInfo->Header.Size = sizeof (EFI_RISCV_MM_BOOT_INFO);
  BootInfo->Header.Attr = EFI_PARAM_ATTR_APTEE;

  BootInfo->MmMemBase = MmVmMemBase;
  BootInfo->MmMemLimit = BootInfo->MmMemBase + MmVmMemSize - 1;
  BootInfo->MmImageBase = MmVmMemBase + MM_VM_RAM_IMAGE_START_OFFSET;
  BootInfo->MmImageSize = PcdGet32 (PcdRiscVStandaloneMmFvSize);
  BootInfo->MmNsCommBufBase = BootInfo->MmMemBase + MM_VM_RAM_MM_SHARED_BUF_OFFSET;
  BootInfo->MmNsCommBufSize = MM_VM_RAM_MM_SHARED_BUF_SIZE;
  BootInfo->MmStackBase = BootInfo->MmMemBase + MM_VM_BOOT_STACK_OFFSET + MM_VM_BOOT_STACK_SIZE;
  BootInfo->MmHeapBase = BootInfo->MmMemBase + MM_VM_BOOT_HEAP_OFFSET;
  BootInfo->MmHeapSize = MM_VM_BOOT_HEAP_SIZE;
  BootInfo->MmPcpuStackSize = 0x1000;
  BootInfo->NumMmMemRegions = 6;

  // CPU info. Only 1 supported for now.
  BootInfo->NumCpus = 1;
  CpuInfo = &(BootInfo->CpuInfo);
  CpuInfo->ProcessorId = 0;
  CpuInfo->Core = 0;
  CpuInfo->Package = 0;
  CpuInfo->Flags = CPU_INFO_FLAG_PRIMARY_CPU;
}

EFI_STATUS
EFIAPI
StandaloneMmInitialization (IN OUT UINT64 *TvmGuestId)
{
  SBI_RET                         Ret;
  TSM_INFO                        TsmInfo;
  UINT64                          MmBase, PageStart, StackBottom, HeapStart;
  UINT64                          MmSize, MmTvmSize, NumPtePages;
  TVM_CREATE_PARAMS               TvmCreateParams;
  EFI_RISCV_MM_BOOT_INFO          *BootInfo;
  UINTN                           BootInfoSize;

  if (TvmGuestId == NULL || PcdGet32 (PcdRiscVStandaloneMmFvSize) == 0) {
    return EFI_INVALID_PARAMETER;
  }

  // Check TSM info
  Ret = SbiTeeHostGetTsmInfo ((UINT64)&TsmInfo, sizeof (TsmInfo));
  if (Ret.Error != SBI_TEE_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "%a: Cound not get TSM info, ret:%d\n", __func__, Ret.Error));
    return EFI_NOT_STARTED;
  }

  if (TsmInfo.TsmState != TSM_READY) {
    DEBUG ((DEBUG_ERROR, "%a: TSM not ready\n", __func__));
    return EFI_NOT_READY;
  }

  //
  // |---------------------------------------------------------------------------------------------- |
  // | Tee TvmState | Tee Page Tables | Tee Boot Info + Stack + Heap + Tee FV | Tee page zero Memory |
  // |---------------------------------------------------------------------------------------------- |
  //
  MmSize = ALIGN_VALUE (PcdGet64 (PcdRiscVStandaloneMmMemSize), SIZE_4KB);
  ASSERT (MmSize >= MM_VM_RAM_MIN_SIZE);

  MmBase = (UINT64)AllocateReservedPages (MmSize / EFI_PAGE_SIZE);
  if (MmBase == 0) {
    DEBUG ((DEBUG_ERROR, "%a: Error while allocating reserved memory for MM\n", __func__));
    return EFI_OUT_OF_RESOURCES;
  }

  // TVM Create param
  PageStart = ALIGN_VALUE (MmBase, SIZE_16KB);
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart, TsmInfo.TvmStatePages + 4));
  TvmCreateParams.TvmPageDirectoryAddr = PageStart;
  TvmCreateParams.TvmStateAddr = TvmCreateParams.TvmPageDirectoryAddr + SIZE_16KB;
  Ret = SbiTeeHostCreateTvm ((UINT64)&TvmCreateParams, sizeof (TvmCreateParams));
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  *TvmGuestId = Ret.Value;
  PageStart += (TsmInfo.TvmStatePages + 4) * SIZE_4KB;

  // Add 1 Vcpu
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart,
                                        TsmInfo.TvmVcpuStatePages));
  Ret = SbiTeeHostCreateTvmVcpu (*TvmGuestId,
                                  RISCV_TEE_VCPU_ID,
                                  PageStart);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart += TsmInfo.TvmVcpuStatePages * SIZE_4KB;

  // Add page tables pages
  MmTvmSize = MmSize - (PageStart - MmBase);
  NumPtePages = CalculateMaxPtePages (MmTvmSize);
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart, NumPtePages));
  Ret = SbiTeeHostAddTvmPageTablePages (*TvmGuestId, PageStart, NumPtePages);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart += NumPtePages * SIZE_4KB;

  // Add usable memory region for TVM
  MmTvmSize = MmSize - (PageStart - MmBase);
  Ret = SbiTeeHostAddTvmMemoryRegion (*TvmGuestId, MM_VM_RAM_BASE, MmTvmSize);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Add boot info to measured data
  BootInfoSize = sizeof (EFI_RISCV_MM_BOOT_INFO);
  ASSERT (BootInfoSize < MM_VM_BOOT_INFO_SIZE);
  BootInfo = (EFI_RISCV_MM_BOOT_INFO *)AllocateAlignedPages (MM_VM_BOOT_INFO_SIZE / EFI_PAGE_SIZE, SIZE_4KB);
  if (BootInfo == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: Error while allocating memory for boot info\n", __func__));
    FreePages ((VOID *)MmBase, MmSize / EFI_PAGE_SIZE);
    return EFI_OUT_OF_RESOURCES;
  }
  SetMem ((VOID *)BootInfo, MM_VM_BOOT_INFO_SIZE, 0);
  CreateMmBootInfo (BootInfo, MM_VM_RAM_BASE, MmTvmSize);
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart, MM_VM_BOOT_INFO_SIZE / SIZE_4KB));
  Ret = SbiTeeHostAddTvmMeasuredPages (*TvmGuestId, (UINT64)BootInfo,
                                        PageStart,
                                        TSM_PAGE_4K, MM_VM_BOOT_INFO_SIZE / SIZE_4KB,
                                        MM_VM_RAM_BASE + MM_VM_BOOT_INFO_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  FreePages ((VOID *)BootInfo, MM_VM_BOOT_INFO_SIZE / EFI_PAGE_SIZE);
  PageStart +=  MM_VM_BOOT_INFO_SIZE;

  // Convert the stack memory
  StackBottom = PageStart;
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart,
                                        MM_VM_BOOT_STACK_SIZE / SIZE_4KB));
  PageStart += MM_VM_BOOT_STACK_SIZE;

  // Convert the heap memory
  HeapStart = PageStart;
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart,
                                        MM_VM_BOOT_HEAP_SIZE / SIZE_4KB));
  PageStart += MM_VM_BOOT_HEAP_SIZE;

  // Add FV MM to measured data
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart,
                                        PcdGet32 (PcdRiscVStandaloneMmFvSize) / SIZE_4KB));

  Ret = SbiTeeHostAddTvmMeasuredPages (*TvmGuestId, PcdGet64 (PcdRiscVStandaloneMmFdBase),
                                        PageStart,
                                        TSM_PAGE_4K, PcdGet32 (PcdRiscVStandaloneMmFvSize) / SIZE_4KB,
                                        MM_VM_RAM_BASE + MM_VM_RAM_IMAGE_START_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart += PcdGet32 (PcdRiscVStandaloneMmFvSize);

  // Convert the rest of MM memory
  if ((MmSize - (PageStart - MmBase)) <
        (MmTvmSize - (MM_VM_RAM_IMAGE_START_OFFSET + PcdGet32 (PcdRiscVStandaloneMmFvSize)))) {
    MmTvmSize = MmSize - (PageStart - MmBase);
  } else {
    MmTvmSize = MmTvmSize - (MM_VM_RAM_IMAGE_START_OFFSET + PcdGet32 (PcdRiscVStandaloneMmFvSize));
  }
  ASSERT_EFI_ERROR (ConvertToConfidentialMemory (PageStart,
                                        MmTvmSize / SIZE_4KB));

  // Finalize the TVM
  Ret = SbiTeeHostFinalizeTvm (*TvmGuestId,
                                MM_VM_RAM_BASE + MM_VM_RAM_IMAGE_START_OFFSET,
                                MM_VM_RAM_BASE + MM_VM_BOOT_INFO_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Add page zeros to the rest of MM meory
  Ret = SbiTeeHostAddTvmZeroPages (*TvmGuestId, PageStart,
                                    TSM_PAGE_4K, MmTvmSize / SIZE_4KB,
                                    MM_VM_RAM_BASE +
                                    MM_VM_RAM_IMAGE_START_OFFSET + PcdGet32 (PcdRiscVStandaloneMmFvSize));
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Add page zeros to the stack memory
  Ret = SbiTeeHostAddTvmZeroPages (*TvmGuestId, StackBottom,
                                    TSM_PAGE_4K, MM_VM_BOOT_STACK_SIZE / SIZE_4KB,
                                    MM_VM_RAM_BASE + MM_VM_BOOT_STACK_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Add page zeros to the heap memory
  Ret = SbiTeeHostAddTvmZeroPages (*TvmGuestId, HeapStart,
                                    TSM_PAGE_4K, MM_VM_BOOT_HEAP_SIZE / SIZE_4KB,
                                    MM_VM_RAM_BASE + MM_VM_BOOT_HEAP_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  return EFI_SUCCESS;
}
