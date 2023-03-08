/** @file
  RISC-V TEE library common definition.

  Copyright (c) 2023, Ventana Micro System Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef RISCV_TEE_LIB_H_
#define RISCV_TEE_LIB_H_

#include <Library/BaseRiscVSbiLib.h>

enum SBI_TEE_ERR {
  SBI_TEE_SUCCESS = 0,
  SBI_TEE_ERR_INVAL_ADDR,
  SBI_TEE_ERR_INVAL_PARAM,
  SBI_TEE_ERR_FAILED,
  SBI_TEE_ERR_ALREADY_STARTED,
  SBI_TEE_ERR_OUT_OF_PTPAGES,
};

enum TSM_PAGE_TYPE {
  TSM_PAGE_4K = 0,
  TSM_PAGE_2M = 1,
  TSM_PAGE_1GB = 2,
  TSM_PAGE_512 = 3
};

enum TVM_STATE {
  /* The TVM has been created, but isn't yet ready to run */
  TVM_INITIALIZING = 0,
  /* The TVM is in a runnable state */
  TVM_RUNNABLE = 1,
};

enum TVM_MEMORY_REGION_TYPE {
/*
  * Reserved for mapping confidential pages. The region is initially unpopulated,
  * and pages
  * of confidential memory can be inserted by calling
  * `SbiTeeHostAddTvmZeroPages()` and
  * `SbiTeeHostAddTvmMeasuredPages().
  */
TVM_CONFIDENTIAL_REGION = 0,
/*
  * The region is initially unpopulated, and pages of shared memory may be inserted
  * by calling
  * `SbiTeeHostAddTvmSharedPages()`. Attempts by a TVM VCPU to access an
  * unpopulated region
  * will cause a `SHARED_PAGE_FAULT` exit from `SbiTeeHostRunTvmVcpu()`.
  */
TVM_SHARED_MEMORY_REGION = 1,
/*
  * The region is unpopulated; attempts by a TVM VCPU to access this region will
  * cause a
  * `MMIO_PAGE_FAULT` exit from `SbiTeeHostRunTvmVcpu()`.
  */
TVM_EMULATED_MMIO_REGION = 2,
};

enum VCPU_REGISTER_SET_ID {
  /* General purpose registers */
  GPRS = 0,
  /* Supervisor CSRs */
  SUPERVISOR_CSRS = 1,
  /* Hypervisor (HS-level) CSRs */
  HYPERVISOR_CSRS = 2,
};

/*
 * General purpose registers for he TVM VCPU.
 * Corresponds to `GPRS` in `vcpu_register_set_id`.
 */
typedef struct {
  /*
   * Indexed VCPU GPRs from X0 - X31.
   *
   * The TSM will always read or write the minimum number of registers in this set
   * to 60 complete the requested action, in order to avoid leaking information from the
   * TVM.
   *
   * The TSM will write to these registers upon return from `TvmCpuRun` when:
   * 1) The VCPU takes a store guest page fault in an emulated MMIO region.
   * 2) The VCPU makes an ECALL that is to be forwarded to the host.
   *
   * The TSM will read from these registers when:
   * 1) The VCPU takes a load guest page fault in an emulated MMIO region.
   * 2) The host calls `SbiTeeHostFinalizeTvm()`, latching the entry point
   * argument
   * (stored in 'A1') for the boot VCPU.
   *
   */
  UINT64 Gprs[32];
} TVM_VCPU_SUPERVISOR_GPRS;

/*
 * Hypervisor [HS-level] CSRs.
 * Corresponds to `HYPERVISOR_CSRS` in `VCPU_REGISTER_SET_ID`.
 */
typedef struct {
  /*
   *
   * HtVal value for guest page faults taken by the TVM vCPU. Written by the TSM
   * upon return from `SbiTeeHostRunTvmVcpu()`.
   *
   */
  UINT64 HtVal;
  
  /*
   *
   * HtInst value for guest page faults or virtual instruction exceptions taken by
   * the TVM vCPU.
   *
   * The TSM will only write `htinst` in the following cases:
   *
   * MMIO load page faults. The value written to the register in `Gprs`
   * corresponding to the
   * 'rd' register in the instruction will be used to complete the load upon the
   * next call to  `SbiTeeHostRunTvmVcpu()` for this vCPU.
   *
   * MMIO store page faults. The TSM will write the value to be stored by the vCPU
   * to the register in `Gprs` corresponding to the 'rs2' register in the instruction upon
   * return from `SbiTeeHostRunTvmVcpu()`.
   *
   */
  UINT64 HtInst;
} TVM_VCPU_HYPERVISOR_CSRS;

/*
 * Supervisor-level CSRs.
 * Corresponds to `SUPERVISOR_CSRS` in `vcpu_register_set_id`.
 */
typedef struct {
  /*
   * Initial SEPC value (entry point) of a TVM vCPU. Latched for the TVM's boot VCPU
   * when SbiTeeHostFinalizeTvm() is called; ignored for all other VCPUs.
   */
  UINT64 Sepc;

  /*
   * SCAUSE value for the trap taken by the TVM vCPU. Written by the TSM upon return
   * from `SbiTeeHostRunTvmVcpu()`
   */
  UINT64 Scause;

  /*
   * STVAL value for guest page faults or virtual instruction exceptions taken by
   * the TVM VCPU. Written by the TSM upon return from SbiTeeHostRunTvmVcpu()
   *
   * Note that guest virtual addresses are not exposed by the TSM, so only the 2
   * LSBs will ever be non-zero for guest page fault exceptions.
   */
  UINT64 Stval;
} TVM_VCPU_SUPERVISOR_CSRS;

typedef struct {
  /*
   * A value of enum type `VCPU_REGISTER_SET_ID`.
   */
  UINT16 Id;

  /*
   * The offset of the register set from the start of the VCPU's shared-memory state
   * area.
   */
  UINT16 Offset;
} TVM_VCPU_REGISTER_SET_LOCATION;

enum TVM_INTERRUPT_EXIT {
  /* Refer to the privileged spec for details. */
  USER_SOFT = 0,
  SUPERVISOR_SOFT = 1,
  VIRTUAL_SUPERVISOR_SOFT = 2,
  MACHINE_SOFT = 3,
  USER_TIMER = 4,
  SUPERVISOR_TIMER = 5,
  VIRTUAL_SUPERVISOR_TIMER = 6,
  MACHINE_TIMER = 7,
  USER_EXTERNAL = 8,
  SUPERVISOR_EXTERNAL = 9,
  VIRTUAL_SUPERVISOR_EXTERNAL = 10,
  MACHINE_EXTERNAL = 11,
  SUPERVISOR_GUEST_EXTERNAl = 12,
};

enum TVM_EXCEPTION {
  /* Refer to the privileged spec for details. */
  INSTRUCTION_MISALIGNED = 0,
  INSTRUCTION_FAULT = 1,
  ILLEGAL_INSTRUCTION = 2,
  BREAKPOINT = 3,
  LOAD_MISALIGNED = 4,
  LOAD_FAULT = 5,
  STORE_MISALIGNED = 6,
  STORE_FAULT = 7,
  USER_ENVCALL = 8,
  SUPERVISOR_ENVCALL = 9,

  /*
   * The TVM made an ECALL request directed at the host.
   * The host should examine GPRs A0-A7 in the `TVM_VCPU_SUPERVISOR_GPRS`
   * area of the VCPU shared-memory region to process the ECALL.
   */
  VIRTUAL_SUPERVISOR_ENV_CALL = 10,
 
  /* Refer to the privileged spec for details. */
  MACHINE_ENVCALL = 11,
  INSTRUCTION_PAGE_FAULT = 12,
  LOAD_PAGE_FAULT = 13,
  STORE_PAGE_FAULT = 15,
  GUEST_INSTRUCTION_PAGE_FAULT = 20,

  /*
   * The TVM encountered a load fault in a confidential, MMIO, or shared-memory
   * region. The host should determine the fault address by retrieving the
   * `Htval` from `TVM_VCPU_HYPERVISOR_CSRS` and `Stval` from
   * `TVM_VCPU_SUPERVISOR_CSRS`
   * and combining them as follows: "(Htval << 2) | (Stval & 0x3)". The fault
   * address can then be used to determine the type of memory region, and making the
   * appropriate call (example: SbiTeeHostAddTvmZeroPages() to add a demand-zero
   * confidential page if applicable), and then calling SbiTeeHostRunTvmVcpu to resume
   * execution at the following instruction.
   */
  GUEST_LOAD_PAGE_FAULT = 21,

  /*
  * The TVM executed an instruction that caused an exit. The host should decode the
  * instruction by examining `Stval` from `TVM_VCPU_SUPERVISOR_CSRS`, and determine
  * the further course of action, and calling then calling
  * SbiTeeHostRunTvmVcpu
  * if appropriate to resume execution at the following instruction.
  */
  VIRTUAL_INSTRUCTION = 22,

  /*
  * The TVM encountered a store fault in a confidential, MMIO, or shared-memory
  * region. The host should determine the fault address by retrieving the
  * `Htval` from `TVM_VCPU_HYPERVISOR_CSRS` and `Stval` from
  * `SbiTeeHostRunTvmVcpu` and combining them as follows:
  * "(Htval << 2) | (Stval & 0x3)". The fault address
  * can then be used to determine the type of memory region, and making the
  * appropriate call (example: SbiTeeHostAddTvmZeroPages() to add a demand-zero
  * confidential page if applicable), and then calling SbiTeeHostRunTvmVcpu to resume
  * execution at the following instruction.
  */
  GUEST_STORE_PAGE_FAULT = 23,
};

enum TSM_STATE {
  /* TSM has not been loaded on this platform. */
  TSM_NOT_LOADED = 0,
  /* TSM has been loaded, but has not yet been initialized. */
  TSM_LOADED = 1,
  /* TSM has been loaded & initialized, and is ready to accept ECALLs.*/
  TSM_READY = 2
};

typedef struct {
  /*
   * The current state of the TSM (see tsm_state enum above). If the state is not
   * TSM_READY, the remaining fields are invalid and will be initialized to 0.
   */
  UINT32 TsmState;

  /* Version number of the running TSM. */
  UINT32 TsmVersion;

  /*
   * The number of 4KiB pages which must be donated to the TSM for storing TVM
   * state in SbiTeeHostCreateTvmVcpu().
   */
  UINT64 TvmStatePages;

  /* The maximum number of VCPUs a TVM can support. */
  UINT64 TvmMaxVcpus;

  /*
   * The number of 4kB pages which must be donated to the TSM when
   * creating a new VCPU.
   */
  UINT64 TvmVcpuStatePages;
} TSM_INFO;

typedef struct {
  /*
   * The base physical address of the 16KiB confidential memory region
   * that should be used for the TVM's page directory. Must be 16KiB-aligned.
   */
  UINT64 TvmPageDirectoryAddr;

  /*
   * The base physical address of the confidential memory region to be used
   * to hold the TVM's state. Must be page-aligned and the number of
   * pages must be at least the value returned in TSM_INFO.TvmStatePages
   * returned by the call to SbiTeeHostGetTsmInfo().
   */
  UINT64 TvmStateAddr;
} TVM_CREATE_PARAMS;

typedef struct {
  /*
   * The base address of the virtualized IMSIC in TVM physical address space.
   *
   * IMSIC addresses follow the below pattern:
   *
   * XLEN-1 >=24 12 0 | | | |
   *
   * |xxxxxx|Group Index|xxxxxxxxxxx|Hart Index|Guest Index| 0 |
   *
   * The base address is the address of the IMSIC with group ID, hart ID, and guest
   * ID of 0.
   */
  UINT64 ImsicBaseAddr;
  /* The number of group index bits in an IMSIC address. */
  UINT32 GroupIndexBits;
  /* The location of the group index in an IMSIC address. Must be >= 24. */
  UINT32 GroupIndexShift;
  /* The number of hart index bits in an IMSIC address. */
  UINT32 HartIndexBits;
  /* The number of guest index bits in an IMSIC address. Must be >=
   * log2(guests_per_hart + 1).
   */
  UINT32 GuestIndexBits;
  /*
   * The number of guest interrupt files to be implemented per VCPU. Implementations
   * may reject
   * configurations with guests_per_hart > 0 if nested IMSIC virtualization is not
   * supported.
   */
  UINT32 GuestsPerHart;
} TVM_AIA_PARAMS;

/* TODO: Define real MAX_MEASUREMENT_REGISTERS*/
#define MAX_MEASUREMENT_REGISTERS 128

enum TEE_HASH_ALGORITHM {
  /* SHA-384 */
  SHA384,
  /* SHA-512 */
  SHA512
};

enum TEE_EVIDENCE_FORMAT {
  DiceTcbINfo = 0,
  DiceMultiTcbINfo = 1,
  OOpenDice = 2
};

typedef struct  {
  /* The TCB Secure Version Number. */
  UINT64 TcbSvn;
  /* The supported hash algorithm */
  enum TEE_HASH_ALGORITHM HashAlgorithm;
  /* The supported evidence formats. This is a bitmap */
  UINT32 EvidenceFormats;
  /* Number of static measurement registers */
  UINT8 StaticMeasurements;
  /* Number of runtime measurement registers */
  UINT8 RuntimeMeasurements;
  /* Array of all measurement register descriptors */
  UINT64 MsmtRegs[MAX_MEASUREMENT_REGISTERS];
} TEE_ATTESTATION_CAPABILITIES;

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
  );

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
  );

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
  );

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
SbiTeeHostGlobalFence (VOID);

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
SbiTeeHostLocalFence (VOID);

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
);

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
  );

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
  );

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
  );


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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  Init TVM AIA

  Configures AIA virtualization for the TVM identified by TvmGuestId based on the parameters in the
  TVM_AIA_PARAMS structure at the non-confidential physical address at TvmAiaParamsAddr. The
  TvmAiaParamsLen is the byte-length of the TVM_AIA_PARAMS structure.
  This cannot be called after SbiTeeHostFinalizeTvm()

  @param[in] TvmGuestId         The Tvm Guest Id.
  @param[in] TvmAiaParamsAddr   The address holds the TVM_AIA_PARAMS structure.
  @param[in] TvmAiaParamsLen    The len of the TvmAiaParamsAddr.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The TvmAiaParamsAddr was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId or TvmAiaParamsLen was invalid, or
                                                    the TVM wasn't in TVM_INITIALIZING state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeInterruptInitTvmAia (
  IN UINT64 TvmGuestId,
  IN UINT64 TvmAiaParamsAddr,
  IN UINT64 TvmAiaParamsLen
  );

/**
  Set TVM AIA Cpu Imsic address.

  Sets the guest physical address of the specified VCPU’s virtualized IMSIC to TvmVcpuImsicGpa. The
  TvmVcpuImsicGpa must be valid for the AIA configuration that was set by
  SbiTeeInterruptInitTvmAia(). No two VCPUs may share the same TvmVcpuImsicGpa.
  This can be called only after SbiTeeInterruptInitTvmAia() and before
  SbiTeeHostFinalizeTvm(). All VCPUs in an AIA-enabled TVM must have their IMSIC
  configuration set prior to calling SbiTeeHostFinalizeTvm().

  @param[in] TvmGuestId         The Tvm Guest Id.
  @param[in] TvmVcpuId          The Vcpu Id.
  @param[in] TvmVcpuImsicGpa    The guest physical address of Vcpu's IMSIC.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The TvmVcpuImsicGpa was invalid.
                                SBI_TEE_ERR_INVAL_PARAM: TvmGuestId or TvmVcpuId was invalid, or
                                                    the TVM wasn't in TVM_INITIALIZING state.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeInterruptSetTvmAiaCpuImsicAddr (
  IN UINT64 TvmGuestId,
  IN UINT64 TvmAiaParamsAddr,
  IN UINT64 TvmAiaParamsLen
  );

/**
  Convert AIA IMSIC.

  Starts the process of converting the non-confidential guest interrupt file at ImsicPageAddr for use
  with a TVM. This must be followed by calls to SbiTeeHostGlobalFence() and
  SbiTeeHostLocalFence() before the interrupt file can be assigned to a TVM

  @param[in] ImsicPageAddr      The non-confidential guest intterupt file address.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The ImsicPageAddr was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeInterruptConvertAiaImsic (
  IN UINT64 ImsicPageAddr
  );

/**
  Reclaim AIA IMSIC.

  Reclaims the confidential TVM interrupt file at ImsicPageAddr. The interrupt file must not
  currently be assigned to a TVM.

  @param[in] ImsicPageAddr      The confidential guest intterupt file address.

  @param[out]                 SBI_RET.Error value as described below:
                                SBI_TEE_SUCCESS: The operation completed successfully.
                                SBI_TEE_ERR_INVAL_ADDR: The ImsicPageAddr was invalid.
                                SBI_TEE_ERR_FAILED: The operation failed for unknown reasons.
**/
SBI_RET
EFIAPI
SbiTeeInterruptReclaimTvmAiaImsic (
  IN UINT64 ImsicPageAddr
  );

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
  );

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
  );

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
  );

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
  );

#endif /* RISCV_TEE_LIB_H_ */
