/** @file
  RISC-V TEE Guest calling implementation.

  Copyright (c) 2023, Ventana Micro System Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/


#include <Uefi.h>
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseRiscVSbiLib.h>
#include <Library/BaseRiscVTeeLib.h>

#define SBI_TEE_TEE_EID          0x434F5647

#define SBI_TEE_GUEST_CALL(Fid, Num, ...) \
              SbiCall (SBI_TEE_TEE_EID, Fid, Num, ##__VA_ARGS__)

enum {
  SBI_TEE_GUEST_FID_ADD_MMIO_MEMORY_REGION = 0,
  SBI_TEE_GUEST_FID_REMOVE_MMIO_MEMORY_REGION = 1,
  SBI_TEE_GUEST_FID_SHARE_MEMORY_REGION = 2,
  SBI_TEE_GUEST_FID_UNSHARE_MEMORY_REGION = 3,
  SBI_TEE_GUEST_MAX_FUNC = 4
};

/**
  Guest adds MMIO memory region

  Marks the range of TVM physical address space starting at TvmGpaAddr as MMIO region.

  Both TvmGpaAddr and RegionLen must be 4kB-aligned.

  @param[in] TvmGpaAddr           The guest physical address.
  @param[in] RegionLen            The length of region

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_PARAM: The TvmGpaAddr or RegionLen was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeGuestAddMmioMemoryRegion (
  IN UINT64 TvmGpaAddr,
  IN UINT64 RegionLen
  )
{
  return SBI_TEE_GUEST_CALL (SBI_TEE_GUEST_FID_ADD_MMIO_MEMORY_REGION, 2,
                              TvmGpaAddr, RegionLen);
}

/**
  Guest removes MMIO memory region

  Remove the range of TVM physical address space starting at TvmGpaAddr as MMIO region.

  Both TvmGpaAddr and RegionLen must be 4kB-aligned.

  @param[in] TvmGpaAddr           The guest physical address.
  @param[in] RegionLen            The length of region

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_PARAM: The TvmGpaAddr or RegionLen was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeGuestRemoveMmioMemoryRegion (
  IN UINT64 TvmGpaAddr,
  IN UINT64 RegionLen
  )
{
  return SBI_TEE_GUEST_CALL (SBI_TEE_GUEST_FID_REMOVE_MMIO_MEMORY_REGION, 2,
                              TvmGpaAddr, RegionLen);
}

/**
  Guest shares a memory region

  Initiates the assignment-change of TVM physical address space starting at TvmGpaAddr from
  confidential to non-confidential/shared memory. The requested range must lie within an existing
  region of confidential address space, and may or may not be populated. If the region of address
  space is populated, the TSM invalidates the pages and marks the region as pending assignment
  change to shared. The host must complete a TVM TLB invalidation sequence, initiated by
  SbiTeeHostTvmFence(), in order to complete the assignment-change. The calling TVM vCPU is
  considered blocked until the assignment-change is completed; attempts to run it with
  SbiTeeHostRunTvmVcpu() will fail. Any guest page faults taken by other TVM vCPUs in this region prior to
  completion of the assignment-change are considered fatal. The host may not insert any pages in the
  region prior to completion of the assignment-change. Upon completion, the host may reclaim the
  confidential pages that were previously mapped in the region using SbiTeeHostReclaimPages()
  and may insert shared pages into the region using SbiTeeHostAddTvmSharedPages(). If the range of
  address space is completely unpopulated, the region is immediately mapped as shared and the host
  may insert shared pages.

  Both TvmGpaAddr and RegionLen must be 4kB-aligned.

  @param[in] TvmGpaAddr           The guest physical address.
  @param[in] RegionLen            The length of region

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The TvmGpaAddr was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: The RegionLen was invalid or
                                  the entire range doesn't span a CONFIDENTIAL_REGION
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeGuestShareMemoryRegion (
  IN UINT64 TvmGpaAddr,
  IN UINT64 RegionLen
  )
{
  return SBI_TEE_GUEST_CALL (SBI_TEE_GUEST_FID_SHARE_MEMORY_REGION, 2,
                              TvmGpaAddr, RegionLen);
}

/**
  Guest unshares a memory region

  Initiates the assignment-change of TVM physical address space starting at TvmGpaAddr from shared
  to confidential. The requested range must lie within an existing region of non-confidential address
  space, and may or may not be populated. If the region of address space is populated, the TSM
  invalidates the pages and marks the region as pending assignment-change to confidential. The host
  must complete a TVM TLB invalidation sequence, initiated by SbiTeeHostTvmFence(), in
  order to complete the assignment-change. The calling TVM vCPU is considered blocked until the
  assignment-change is completed; attempts to run it with SbiTeeHostRunTvmVcpu() will fail. Any guest
  page faults taken by other TVM vCPUs in this region prior to completion of the assignment-change
  are considered fatal. The host may not insert any pages in the region prior to completion of the
  assignment-change. Upon completion, the host may (if required) convert host memory pages using
  SbiTeeHostConvertPages() and may assign un-assigned confidential pages into the region using
  SbiTeeHostAddTvmZeroPages(). If the range of address space is unpopulated, the host may
  insert zero pages on faults during TVM access.
  
  Both TvmGpaAddr and RegionLen must be 4kB-aligned.

  @param[in] TvmGpaAddr           The guest physical address.
  @param[in] RegionLen            The length of region

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The TvmGpaAddr was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: The RegionLen was invalid or
                                  the entire range doesn't span a SHARED_MEMORY_REGION
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeGuestUnShareMemoryRegion (
  IN UINT64 TvmGpaAddr,
  IN UINT64 RegionLen
  )
{
  return SBI_TEE_GUEST_CALL (SBI_TEE_GUEST_FID_UNSHARE_MEMORY_REGION, 2,
                              TvmGpaAddr, RegionLen);
}
