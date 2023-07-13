/** @file
  Creates HOB during Standalone MM Foundation entry point
  on RISCV platforms.

Copyright (c) 2017 - 2021, Arm Ltd. All rights reserved.<BR>
Copyright (c) 2023, Ventana Micro System Inc. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <PiPei.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MpInformation.h>

#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/RiscV/StandaloneMmCoreEntryPoint.h>

extern EFI_HOB_HANDOFF_INFO_TABLE *
HobConstructor (
  IN VOID   *EfiMemoryBegin,
  IN UINTN  EfiMemoryLength,
  IN VOID   *EfiFreeMemoryBottom,
  IN VOID   *EfiFreeMemoryTop
  );

// GUID to identify HOB with whereabouts of communication buffer with Normal
// World
extern EFI_GUID  gEfiStandaloneMmNonSecureBufferGuid;

// GUID to identify HOB where the entry point of the CPU driver will be
// populated to allow this entry point driver to invoke it upon receipt of an
// event
extern EFI_GUID  gEfiMmCpuDriverEpDescriptorGuid;

/**
  Use the boot information passed by privileged firmware to populate a HOB list
  suitable for consumption by the MM Core and drivers.

  @param  [in, out] CpuDriverEntryPoint   Address of MM CPU driver entrypoint
  @param  [in]      PayloadBootInfo       Boot information passed by privileged
                                          firmware

**/
VOID *
CreateHobListFromBootInfo (
  IN  OUT  PI_MM_CPU_DRIVER_ENTRYPOINT  *CpuDriverEntryPoint,
  IN       EFI_RISCV_MM_BOOT_INFO       *PayloadBootInfo
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE       *HobStart;
  EFI_RESOURCE_ATTRIBUTE_TYPE      Attributes;
  UINT32                           Index;
  UINT32                           BufferSize;
  UINT32                           Flags;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK   *MmramRangesHob;
  EFI_MMRAM_DESCRIPTOR             *MmramRanges;
  EFI_MMRAM_DESCRIPTOR             *NsCommBufMmramRange;
  MP_INFORMATION_HOB_DATA          *MpInformationHobData;
  EFI_PROCESSOR_INFORMATION        *ProcInfoBuffer;
  EFI_RISCV_MM_CPU_INFO            *CpuInfo;
  MM_CPU_DRIVER_EP_DESCRIPTOR      *CpuDriverEntryPointDesc;

  // Create a hoblist with a PHIT and EOH
  HobStart = HobConstructor (
               (VOID *)(UINTN)PayloadBootInfo->MmMemBase,
               (UINTN)PayloadBootInfo->MmMemLimit - PayloadBootInfo->MmMemBase,
               (VOID *)(UINTN)PayloadBootInfo->MmHeapBase,
               (VOID *)(UINTN)(PayloadBootInfo->MmHeapBase + PayloadBootInfo->MmHeapSize)
               );

  // Check that the Hoblist starts at the bottom of the Heap
  ASSERT (HobStart == (VOID *)(UINTN)PayloadBootInfo->MmHeapBase);

  // Build a Boot Firmware Volume HOB
  BuildFvHob (PayloadBootInfo->MmImageBase, PayloadBootInfo->MmImageSize);

  // Build a resource descriptor Hob that describes the available physical
  // memory range
  Attributes = (
                EFI_RESOURCE_ATTRIBUTE_PRESENT |
                EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
                EFI_RESOURCE_ATTRIBUTE_TESTED |
                EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
                EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
                EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
                EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE
                );

  BuildResourceDescriptorHob (
    EFI_RESOURCE_SYSTEM_MEMORY,
    Attributes,
    (UINTN)PayloadBootInfo->MmMemBase,
    PayloadBootInfo->MmMemLimit - PayloadBootInfo->MmMemBase
    );

  // Find the size of the GUIDed HOB with MP information
  BufferSize  = sizeof (MP_INFORMATION_HOB_DATA);
  BufferSize += sizeof (EFI_PROCESSOR_INFORMATION) * PayloadBootInfo->NumCpus;

  // Create a Guided MP information HOB to enable the CPU driver to
  // perform per-cpu allocations.
  MpInformationHobData = BuildGuidHob (&gMpInformationHobGuid, BufferSize);

  // Populate the MP information HOB with the topology information passed by
  // privileged firmware
  MpInformationHobData->NumberOfProcessors        = PayloadBootInfo->NumCpus;
  MpInformationHobData->NumberOfEnabledProcessors = PayloadBootInfo->NumCpus;
  ProcInfoBuffer                                  = MpInformationHobData->ProcessorInfoBuffer;
  CpuInfo                                         = &(PayloadBootInfo->CpuInfo);

  for (Index = 0; Index < PayloadBootInfo->NumCpus; Index++) {
    ProcInfoBuffer[Index].ProcessorId      = CpuInfo[Index].ProcessorId;
    ProcInfoBuffer[Index].Location.Package = CpuInfo[Index].Package;
    ProcInfoBuffer[Index].Location.Core    = CpuInfo[Index].Core;
    ProcInfoBuffer[Index].Location.Thread  = 0; // not used

    Flags = PROCESSOR_ENABLED_BIT | PROCESSOR_HEALTH_STATUS_BIT;
    if (CpuInfo[Index].Flags & CPU_INFO_FLAG_PRIMARY_CPU) {
      Flags |= PROCESSOR_AS_BSP_BIT;
    }

    ProcInfoBuffer[Index].StatusFlag = Flags;
  }

  // Create a Guided HOB to tell the CPU driver the location and length
  // of the communication buffer shared with the Normal world.
  NsCommBufMmramRange = (EFI_MMRAM_DESCRIPTOR *)BuildGuidHob (
                                                  &gEfiStandaloneMmNonSecureBufferGuid,
                                                  sizeof (EFI_MMRAM_DESCRIPTOR)
                                                  );
  NsCommBufMmramRange->PhysicalStart = PayloadBootInfo->MmNsCommBufBase;
  NsCommBufMmramRange->CpuStart      = PayloadBootInfo->MmNsCommBufBase;
  NsCommBufMmramRange->PhysicalSize  = PayloadBootInfo->MmNsCommBufSize;
  NsCommBufMmramRange->RegionState   = EFI_CACHEABLE | EFI_ALLOCATED;

  // Create a Guided HOB to enable the CPU driver to share its entry
  // point and populate it with the address of the shared buffer
  CpuDriverEntryPointDesc = (MM_CPU_DRIVER_EP_DESCRIPTOR *)BuildGuidHob (
                                                                 &gEfiMmCpuDriverEpDescriptorGuid,
                                                                 sizeof (MM_CPU_DRIVER_EP_DESCRIPTOR)
                                                                 );

  *CpuDriverEntryPoint                         = NULL;
  CpuDriverEntryPointDesc->MmCpuDriverEpPtr    = CpuDriverEntryPoint;

  // Find the size of the GUIDed HOB with SRAM ranges
  BufferSize  = sizeof (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK);
  BufferSize += PayloadBootInfo->NumMmMemRegions * sizeof (EFI_MMRAM_DESCRIPTOR);

  // Create a GUIDed HOB with SRAM ranges
  MmramRangesHob = BuildGuidHob (&gEfiMmPeiMmramMemoryReserveGuid, BufferSize);

  // Fill up the number of MMRAM memory regions
  MmramRangesHob->NumberOfMmReservedRegions = PayloadBootInfo->NumMmMemRegions;
  // Fill up the MMRAM ranges
  MmramRanges = &MmramRangesHob->Descriptor[0];

  // Base and size of memory occupied by the Standalone MM image
  MmramRanges[0].PhysicalStart = PayloadBootInfo->MmImageBase;
  MmramRanges[0].CpuStart      = PayloadBootInfo->MmImageBase;
  MmramRanges[0].PhysicalSize  = PayloadBootInfo->MmImageSize;
  MmramRanges[0].RegionState   = EFI_CACHEABLE | EFI_ALLOCATED;

  // Base and size of buffer shared with privileged Secure world software
  MmramRanges[1].PhysicalStart = PayloadBootInfo->MmSharedBufBase;
  MmramRanges[1].CpuStart      = PayloadBootInfo->MmSharedBufBase;
  MmramRanges[1].PhysicalSize  = PayloadBootInfo->MmSharedBufSize;
  MmramRanges[1].RegionState   = EFI_CACHEABLE | EFI_ALLOCATED;

  // Base and size of buffer used for synchronous communication with Normal
  // world software
  MmramRanges[2].PhysicalStart = PayloadBootInfo->MmNsCommBufBase;
  MmramRanges[2].CpuStart      = PayloadBootInfo->MmNsCommBufBase;
  MmramRanges[2].PhysicalSize  = PayloadBootInfo->MmNsCommBufSize;
  MmramRanges[2].RegionState   = EFI_CACHEABLE | EFI_ALLOCATED;

  // Base and size of memory allocated for stacks for all cpus
  MmramRanges[3].PhysicalStart = PayloadBootInfo->MmStackBase;
  MmramRanges[3].CpuStart      = PayloadBootInfo->MmStackBase;
  MmramRanges[3].PhysicalSize  = PayloadBootInfo->MmPcpuStackSize * PayloadBootInfo->NumCpus;
  MmramRanges[3].RegionState   = EFI_CACHEABLE | EFI_ALLOCATED;

  // Base and size of heap memory shared by all cpus
  MmramRanges[4].PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)HobStart;
  MmramRanges[4].CpuStart      = (EFI_PHYSICAL_ADDRESS)(UINTN)HobStart;
  MmramRanges[4].PhysicalSize  = HobStart->EfiFreeMemoryBottom - (EFI_PHYSICAL_ADDRESS)(UINTN)HobStart;
  MmramRanges[4].RegionState   = EFI_CACHEABLE | EFI_ALLOCATED;

  // Base and size of heap memory shared by all cpus
  MmramRanges[5].PhysicalStart = HobStart->EfiFreeMemoryBottom;
  MmramRanges[5].CpuStart      = HobStart->EfiFreeMemoryBottom;
  MmramRanges[5].PhysicalSize  = HobStart->EfiFreeMemoryTop - HobStart->EfiFreeMemoryBottom;
  MmramRanges[5].RegionState   = EFI_CACHEABLE;

  return HobStart;
}
