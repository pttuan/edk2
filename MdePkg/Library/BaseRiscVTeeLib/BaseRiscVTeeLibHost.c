/** @file
  RISC-V TEE Host calling implementation.

  Copyright (c) 2023, Ventana Micro System Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/


#include <Uefi.h>
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseRiscVSbiLib.h>
#include <Library/BaseRiscVTeeLib.h>

#define SBI_TEE_HOST_EID          0x434F5648

#define SBI_TEE_HOST_CALL(Fid, Num, ...) \
              SbiCall (SBI_TEE_HOST_EID, Fid, Num, ##__VA_ARGS__)

enum {
  SBI_TEE_HOST_FID_TSM_INFO = 0,
  SBI_TEE_HOST_FID_CONVERT_PAGES = 1,
  SBI_TEE_HOST_FID_RECLAIM_PAGES = 2,
  SBI_TEE_HOST_FID_GLOBAL_FENCE = 3,
  SBI_TEE_HOST_FID_LOCAL_FENCE = 4,
  SBI_TEE_HOST_FID_CREATE_TVM = 5,
  SBI_TEE_HOST_FID_FINALIZE_TVM = 6,
  SBI_TEE_HOST_FID_DESTROY_TVM = 7,
  SBI_TEE_HOST_FID_ADD_TVM_MEMORY = 8,
  SBI_TEE_HOST_FID_ADD_TVM_PAGES_TABLE = 9,
  SBI_TEE_HOST_FID_ADD_TVM_MEASURED_PAGES = 10,
  SBI_TEE_HOST_FID_ADD_TVM_ZERO_PAGES = 11,
  SBI_TEE_HOST_FID_ADD_TVM_SHARED_PAGES = 12,
  SBI_TEE_HOST_FID_CREATE_TVM_VCPU = 13,
  SBI_TEE_HOST_FID_RUN_TVM_CPU = 14,
  SBI_TEE_HOST_FID_TVM_FENCE = 15,
  SBI_TEE_HOST_FID_MAX_FUNC = 16
};

/**
  Get the TSM info

  The information returned by the call can be used to determine the current
  stsate of the TSM, and configure parameters for other TVM-related calls.

  @param[in] TsmInfoAddr     The address to store TSM info.
  @param[in] TsmInfoLen      The len that should be the size of the TSM_INFO struct.

  @param[out]                SBI_RET.Error value as described below:
                               SBI_TEE_SUCCESS: The operation completed successfully.
                               SBI_TEE_ERR_INVAL_ADDR: The address was invalid.
                               SBI_TEE_ERR_INVAL_PARAM: The len was insufficient.
                               SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
                             SBI_RET.Value: The number of bytes written to TsmInfoAddr on success.
**/
SBI_RET
EFIAPI
SbiTeeHostGetTsmInfo (
  IN UINT64 TsmInfoAddr,
  IN UINT64 TsmInfoLen
  )
{
  return SBI_TEE_HOST_CALL(SBI_TEE_HOST_FID_TSM_INFO, 2, TsmInfoAddr, TsmInfoLen);
}

/**
  Convert non-confidential memory to confidential memory.

  Begins the process of converting NumPages of non-confidential memory starting at
  BasePageAddr to confidential-memory. On success, pages can be assigned to TVMs
  only following subsequent calls to SbiTeeHostGlobalFence() and SbiTeeHostLocalFence()
  that complete the conversion process. The implied page size is 4KiB.
  
  The BasePageAddr must be page-aligned.

  @param[in] BasePageAddr     The address of memory to be converted.
  @param[in] NumPages         The number of pages to be converted.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The address was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: The number of pages was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostConvertPages (
  IN UINT64 BasePageAddr,
  IN UINT64 NumPages
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_CONVERT_PAGES, 2, BasePageAddr, NumPages);
}

/**
  Reclaim confidential memory.

  Reclaims NumPages of confidential memory starting at BasePageAddr.
  The pages must not be currently assigned to an active TVM.
  The implied page size is 4KiB.

  @param[in] BasePageAddr     The address of memory to be reclaimed.
  @param[in] NumPages         The number of pages to be reclaimed.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The address was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: The number of pages was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostReclaimPages (
  IN UINT64 BasePageAddr,
  IN UINT64 NumPages
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_RECLAIM_PAGES, 2, BasePageAddr, NumPages);
}

/**
  Initiate global fence.

  Initiates a TLB invalidation sequence for all pages marked for conversion via calls to
  SbiTeeHostConvertPages(). The TLB invalidation sequence is completed when SbiTeeHostLocalFence()
  has been invoked on all other CPUs.
  An error is returned if a TLB invalidation sequence is already in progress.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_ALREADY_STARTED: A fence operation is already in progress.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostGlobalFence (VOID)
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_GLOBAL_FENCE, 0);
}

/**
  Invalidates local TLB.

  Invalidates TLB entries for all pages pending conversion by an in-progress TLB invalidation
  peration on the local CPU.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostLocalFence (VOID)
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_LOCAL_FENCE, 0);
}

/**
  Initiate fence for a TVM guest

  Initiates a TLB invalidation sequence for all pages that have been invalidated in the
  given TVM's address space since the previous call to `TvmInitiateFence`. The TLB
  invalidation sequence is completed when all vCPUs in the TVM that were running prior to
  to the call to `TvmInitiateFence` have taken a trap into the TSM, which the host can
  cause by IPI'ing the physical CPUs on which the TVM's vCPUs are running. An error is
  returned if a TLB invalidation sequence is already in progress for the TVM.

  @param[in] TvmGuestId       The Tvm Guest Id.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_ALREADY_STARTED: A fence operation is already in progress.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostTvmFence (
  IN UINT64 TvmGuestId
)
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_TVM_FENCE, 1, TvmGuestId);
}

/**
  Create a TVM.

  Creates a confidential TVM using the specified parameters. The TvmCreateParamsAddr
  is the physical address of the buffer containing the TVM_CREATE_PARAMS structure
  , and TvmCreateParamsLen is the size of the structure in bytes.
  Callers of this API should first invoke SbiTeeHostGetTsmInfo() to obtain information
  about the parameters that should be used to populate TVM_CREATE_PARAMS.

  @param[in] TvmCreateParamsAddr     The address of the TVM_CREATE_PARAMS structure.
  @param[in] TvmCreateParamsLen      The size of  the TVM_CREATE_PARAMS structure.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The address was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: The number of pages was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
                              SBI_RET.Value is Tvm Guest Id on success.
**/
SBI_RET
EFIAPI
SbiTeeHostCreateTvm (
  IN UINT64 TvmCreateParamsAddr,
  IN UINT64 TvmCreateParamsLen
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_CREATE_TVM, 2, TvmCreateParamsAddr, TvmCreateParamsLen);
}

/**
  Finalize a TVM.

  Transitions the TVM specified by TvmGuestId from the "TVM_INITIALIZING" state to a "TVM_RUNNABLE"
  state.

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] EntrySepc        The entry point.
  @param[in] BootArg          The boot argument.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId was invalid,
                                            or the TVM wasn’t in the TVM_INITIALIZING state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostFinalizeTvm (
  IN UINT64 TvmGuestId,
  IN UINT64 EntrySepc,
  IN UINT64 BootArg
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_FINALIZE_TVM, 3, TvmGuestId, EntrySepc, BootArg);
}

/**
  Destroy a TVM.

  Destroys a confidential TVM previously created using SbiTeeHostCreateTvm().
  Confidential TVM memory is automatically released following successful destruction, and it
  can be assigned to other TVMs. Repurposing confidential memory for use by non-confidential
  TVMs requires an explicit call to SbiTeeHostReclaimPages().

  @param[in] TvmGuestId       The Tvm Guest Id.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostDestroyTvm (
  IN UINT64 TvmGuestId
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_DESTROY_TVM, 1, TvmGuestId);
}

/**
  Add a Tvm memory region.

  Marks the range of TVM physical address space starting at TvmGpaAddr as reserved for the
  mapping of confidential memory. The memory region length is specified by RegionLen.
  Both TvmGpaAddr and RegionLen must be 4kB-aligned, and the region must not overlap with a
  previously defined region. This call must not be made after calling SbiTeeHostFinalizeTvm().

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] TvmGpaAddr       The reserved address space
  @param[in] RegionLen        The region length.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The TvmGpaAddr was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId or RegionLen were invalid,
                                                      or the TVM wasn’t in the correct state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostAddTvmMemoryRegion (
  IN UINT64 TvmGuestId,
  IN UINT64 TvmGpaAddr,
  IN UINT64 RegionLen
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_ADD_TVM_MEMORY, 3, TvmGuestId, TvmGpaAddr, RegionLen);
}

/**
  Add Tvm page table pages.

  Adds NumPages confidential memory starting at BasePageAddr to the TVM’s page-table page-
  pool. The implied page size is 4KiB.
  Page table pages may be added at any time, and a typical usecase is in response to a TVM page fault.

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] BasePageAddr     The base of page table pages.
  @param[in] NumPages         The number of pages.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The BasePageAddr was invalid.
                                SBI_TEE_ERR_OUT_OF_PTPAGES: The operation could not complete
                                                  due to insufficient page table pages.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId or NumPages were invalid,
                                                      or the TVM wasn’t in the correct state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostAddTvmPageTablePages (
  IN UINT64 TvmGuestId,
  IN UINT64 BasePageAddr,
  IN UINT64 NumPages
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_ADD_TVM_PAGES_TABLE, 3, TvmGuestId, BasePageAddr, NumPages);
}

/**
  Add Tvm measured pages.

  Copies NumPages pages from non-confidential memory at SourceAddr to confidential memory
  at DestAddr, then measures and maps the pages at DestAddr at the TVM physical address space at
  TvmGuestGpa. The mapping must lie within a region of confidential memory created with
  `SbiTeeHostAddTvmMemoryRegion(). The TsmPageType parameter must be a legal value for
  enum type TsmPageType.

  This call must not be made after calling SbiTeeHostFinalizeTvm().

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] SourceAddr       The source address.
  @param[in] DestAddr         The destination address.
  @param[in] TsmPageType      The type of the pages.
  @param[in] NumPages         The number of pages.
  @param[in] TvmGuestGpa      The TVM guest GPA.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The SourceAddr was invalid or DestAddr
                                                  wasn't in a confidential memory region.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId, TsmPageType or NumPages were invalid,
                                                      or the TVM wasn’t in the TVM_INITIALIZING state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostAddTvmMeasuredPages (
  IN UINT64 TvmGuestId,
  IN UINT64 SourceAddr,
  IN UINT64 DestAddr,
  IN UINT64 TsmPageType,
  IN UINT64 NumPages,
  IN UINT64 TvmGuestGpa
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_ADD_TVM_MEASURED_PAGES, 6, TvmGuestId, SourceAddr,
                        DestAddr, TsmPageType, NumPages, TvmGuestGpa);
}

/**
  Add Tvm zero pages.

  Maps NumPages zero-filled pages of confidential memory starting at BasePageAddr into the
  TVM’s physical address space starting at TvmBasePageAddr. The TvmBasePageAddr must lie
  within a region of confidential memory created with SbiTeeHostAddTvmMemoryRegion(). The
  TsmPageType parameter must be a legal value for the TsmPageType enum. Zero pages for non present
  TVM-specified GPA ranges may be added only post TVM finalization, and are typically
  demand faulted on TVM access.

  This call may be made only after calling SbiTeeHostFinalizeTvm().

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] BasePageAddr     The base page address.
  @param[in] TsmPageType      The type of the pages.
  @param[in] NumPages         The number of pages.
  @param[in] TvmBasePageAddr  The TVM base page address.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The BasePageAddr or TvmBasePageAddr were invalid.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId, TsmPageType or NumPages were invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostAddTvmZeroPages (
  IN UINT64 TvmGuestId,
  IN UINT64 BasePageAddr,
  IN UINT64 TsmPageType,
  IN UINT64 NumPages,
  IN UINT64 TvmBasePageAddr
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_ADD_TVM_ZERO_PAGES, 5, TvmGuestId, BasePageAddr,
                        TsmPageType, NumPages, TvmBasePageAddr);
}

/**
  Add Tvm shared pages.

  Maps NumPages of non-confidential memory starting at BasePageAddr into the TVM’s physical
  address space starting at TvmBasePageAddr. The TvmBasePageAddr must lie within a region
  of non-confidential memory previously defined by the TVM via the guest interface to the TSM. The
  TsmPageType parameter must be a legal value for the TsmPageType enum.

  Shared pages can be added only after the TVM begins execution, and calls the TSM to define the
  location of shared-memory regions.

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] BasePageAddr     The base page address.
  @param[in] TsmPageType      The type of the pages.
  @param[in] NumPages         The number of pages.
  @param[in] TvmBasePageAddr  The TVM base page address.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The BasePageAddr or TvmBasePageAddr were invalid.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId, TsmPageType or NumPages were invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostAddTvmSharedPages (
  IN UINT64 TvmGuestId,
  IN UINT64 BasePageAddr,
  IN UINT64 TsmPageType,
  IN UINT64 NumPages,
  IN UINT64 TvmBasePageAddr
  )
{
    return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_ADD_TVM_SHARED_PAGES, 5, TvmGuestId, BasePageAddr,
                        TsmPageType, NumPages, TvmBasePageAddr);
}

/**
  Create TVM VCPU

  Adds a VCPU with ID VcpuId to the TVM specified by TvmGuestId. TvmStatePageAddr must be
  page-aligned and point to a confidential memory region used to hold the TVM’s vCPU state, and
  must be TSM_INFO::TvmStatePages pages in length.
  
  This call must not be made after calling SbiTeeHostFinalizeTvm(). The host must configure a
  boot VCPU by adding a TvmVcpuId with a value that specified for TvmBootVcpuid in the TVM_CREATE_PARAMS
  structure that was used with SbiTeeTvmCreate().

  @param[in] TvmGuestId               The Tvm Guest Id.
  @param[in] TvmVcpuId                The Vcpu ID.
  @param[in] TvmStatePageAddr         The address that hold the TVM's vCPU state.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId or TvmVcpuId was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeHostCreateTvmVcpu (
  IN UINT64 TvmGuestId,
  IN UINT64 TvmVcpuId,
  IN UINT64 TvmStatePageAddr
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_CREATE_TVM_VCPU, 3, TvmGuestId, TvmVcpuId,
                      TvmStatePageAddr);
}

/**
  Run a TVM VCPU

  Runs the VCPU specified by TvmVcpuId in the TVM specified by TvmGuestId. The TvmGuestId
  must be in a "runnable" state (requires a prior call to SbiTeeHostFinalizeTvm()). The function
  does not return unless the TVM exits with a trap that cannot be handled by the TSM.

  Returns 0 on success in SBI_RET.Value if the TVM exited with a resumable VCPU interrupt or
  exception, and non-zero otherwise. In the latter case, attempts to call SbiTeeHostRunTvmVcpu()
  with the same TvmVcpuId will fail.

  The TSM sets the most significant bit in scause to indicate that that the exit was caused by an
  interrupt, and if this bit is clear, the implication is that the exit was caused by an exception. The
  remaining bits specific information about the interrupt or exception, and the specific reason can be
  determined using the enum TVM_INTERRUPT_EXIT an TVM_EXCEPTION

  @param[in] TvmGuestId       The Tvm Guest Id.
  @param[in] TvmVcpuId        The Vcpu ID.   

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId or TvmVcpuId was invalid, or
                                                    the TVM wasn't in TVM_RUNNABLE state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
                              SBI_RET.Value returns 0 on success if the interrupt or exception is
                                                    resumable. The host can examine scause to
                                                    determine details. Non-zero otherwise.
**/
SBI_RET
EFIAPI
SbiTeeHostRunTvmVcpu (
  IN UINT64 TvmGuestId,
  IN UINT64 TvmVcpuId
  )
{
  return SBI_TEE_HOST_CALL (SBI_TEE_HOST_FID_RUN_TVM_CPU, 2, TvmGuestId, TvmVcpuId);
}
