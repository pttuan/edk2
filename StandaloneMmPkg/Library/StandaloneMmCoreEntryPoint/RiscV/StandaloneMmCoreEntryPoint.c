/** @file
  Entry point to the Standalone MM Foundation when initialized during the SEC
  phase on ARM platforms

Copyright (c) 2017 - 2021, Arm Ltd. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <StandaloneMmCpu.h>
#include <Library/RiscV/StandaloneMmCoreEntryPoint.h>

#include <PiPei.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MpInformation.h>

#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CpuLib.h>
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>
#include <Include/Library/PeCoffLib.h>
#include <Library/BaseRiscVTeeLib.h>

#define BOOT_PAYLOAD_VERSION        1
#define EFI_PARAM_ATTR_APTEE        1

PI_MM_CPU_DRIVER_ENTRYPOINT  CpuDriverEntryPoint = NULL;

/**
  This function locates the Standalone MM Core
  module PE/COFF image in the BFV and returns this information.

  @param  [in]      BfvAddress         Base Address of Boot Firmware Volume
  @param  [in, out] TeData             Pointer to address for allocating memory
                                       for PE/COFF image data
  @param  [in, out] TeDataSize         Pointer to size of PE/COFF image data

**/
STATIC
EFI_STATUS
LocateStandaloneMmCorePeCoffData (
  IN        EFI_FIRMWARE_VOLUME_HEADER  *BfvAddress,
  IN  OUT   VOID                        **TeData,
  IN  OUT   UINTN                       *TeDataSize
  )
{
  EFI_FFS_FILE_HEADER  *FileHeader;
  EFI_STATUS           Status;

  FileHeader = NULL;
  Status     = FfsFindNextFile (
                 EFI_FV_FILETYPE_SECURITY_CORE,
                 BfvAddress,
                 &FileHeader
                 );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Unable to locate Standalone MM FFS file - 0x%x\n",
      Status
      ));
    return Status;
  }

  Status = FfsFindSectionData (EFI_SECTION_PE32, FileHeader, TeData, TeDataSize);
  if (EFI_ERROR (Status)) {
    Status = FfsFindSectionData (EFI_SECTION_TE, FileHeader, TeData, TeDataSize);
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "Unable to locate Standalone MM Section data - %r\n",
        Status
        ));
      return Status;
    }
  }

  DEBUG ((DEBUG_INFO, "Found Standalone MM PE data - 0x%x\n", *TeData));
  return Status;
}

/**
  Returns the PC COFF section information.

  @param  [in, out] ImageContext         Pointer to PE/COFF image context
  @param  [out]     ImageBase            Base of image in memory
  @param  [out]     SectionHeaderOffset  Offset of PE/COFF image section header
  @param  [out]     NumberOfSections     Number of Sections

**/
STATIC
EFI_STATUS
GetPeCoffSectionInformation (
  IN  OUT   PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  OUT   EFI_PHYSICAL_ADDRESS              *ImageBase,
  OUT   UINT32                            *SectionHeaderOffset,
  OUT   UINT16                            *NumberOfSections
  )
{
  RETURN_STATUS                        Status;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_OPTIONAL_HEADER_UNION      HdrData;
  UINTN                                Size;
  UINTN                                ReadSize;

  ASSERT (ImageContext != NULL);
  ASSERT (SectionHeaderOffset != NULL);
  ASSERT (NumberOfSections != NULL);

  Status = PeCoffLoaderGetImageInfo (ImageContext);
  if (RETURN_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: PeCoffLoaderGetImageInfo () failed (Status == %r)\n",
      __func__,
      Status
      ));
    return Status;
  }

  if (ImageContext->SectionAlignment < EFI_PAGE_SIZE) {
    //
    // The sections need to be at least 4 KB aligned, since that is the
    // granularity at which we can tighten permissions.
    //
    if (!ImageContext->IsTeImage) {
      DEBUG ((
        DEBUG_WARN,
        "%a: non-TE Image at 0x%lx has SectionAlignment < 4 KB (%lu)\n",
        __func__,
        ImageContext->ImageAddress,
        ImageContext->SectionAlignment
        ));
      return RETURN_UNSUPPORTED;
    }

    ImageContext->SectionAlignment = EFI_PAGE_SIZE;
  }

  //
  // Read the PE/COFF Header. For PE32 (32-bit) this will read in too much
  // data, but that should not hurt anything. Hdr.Pe32->OptionalHeader.Magic
  // determines if this is a PE32 or PE32+ image. The magic is in the same
  // location in both images.
  //
  Hdr.Union = &HdrData;
  Size      = sizeof (EFI_IMAGE_OPTIONAL_HEADER_UNION);
  ReadSize  = Size;
  Status    = ImageContext->ImageRead (
                              ImageContext->Handle,
                              ImageContext->PeCoffHeaderOffset,
                              &Size,
                              Hdr.Pe32
                              );

  if (RETURN_ERROR (Status) || (Size != ReadSize)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: TmpContext->ImageRead () failed (Status = %r)\n",
      __func__,
      Status
      ));
    return Status;
  }

  *ImageBase = ImageContext->ImageAddress;
  if (!ImageContext->IsTeImage) {
    ASSERT (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE);

    *SectionHeaderOffset = ImageContext->PeCoffHeaderOffset + sizeof (UINT32) +
                           sizeof (EFI_IMAGE_FILE_HEADER);
    *NumberOfSections = Hdr.Pe32->FileHeader.NumberOfSections;

    switch (Hdr.Pe32->OptionalHeader.Magic) {
      case EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        *SectionHeaderOffset += Hdr.Pe32->FileHeader.SizeOfOptionalHeader;
        break;
      case EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        *SectionHeaderOffset += Hdr.Pe32Plus->FileHeader.SizeOfOptionalHeader;
        break;
      default:
        ASSERT (FALSE);
    }
  } else {
    *SectionHeaderOffset = (UINTN)(sizeof (EFI_TE_IMAGE_HEADER));
    *NumberOfSections    = Hdr.Te->NumberOfSections;
    *ImageBase          -= (UINT32)Hdr.Te->StrippedSize - sizeof (EFI_TE_IMAGE_HEADER);
  }

  return RETURN_SUCCESS;
}

/**
  This function locates the section information of
  the Standalone MM Core module to be able to change permissions of the
  individual sections later in the boot process.

  @param  [in]      TeData                Pointer to PE/COFF image data
  @param  [in, out] ImageContext          Pointer to PE/COFF image context
  @param  [out]     ImageBase             Pointer to ImageBase variable
  @param  [in, out] SectionHeaderOffset   Offset of PE/COFF image section header
  @param  [in, out] NumberOfSections      Number of Sections

**/
STATIC
EFI_STATUS
GetStandaloneMmCorePeCoffSections (
  IN        VOID                          *TeData,
  IN  OUT   PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  OUT   EFI_PHYSICAL_ADDRESS              *ImageBase,
  IN  OUT   UINT32                        *SectionHeaderOffset,
  IN  OUT   UINT16                        *NumberOfSections
  )
{
  EFI_STATUS  Status;

  // Initialize the Image Context
  ZeroMem (ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));
  ImageContext->Handle    = TeData;
  ImageContext->ImageRead = PeCoffLoaderImageReadFromMemory;

  DEBUG ((DEBUG_INFO, "Found Standalone MM PE data - 0x%x\n", TeData));

  Status = GetPeCoffSectionInformation (
             ImageContext,
             ImageBase,
             SectionHeaderOffset,
             NumberOfSections
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Unable to locate Standalone MM Core PE-COFF Section information - %r\n", Status));
    return Status;
  }

  DEBUG ((
    DEBUG_INFO,
    "Standalone MM Core PE-COFF SectionHeaderOffset - 0x%x, NumberOfSections - %d\n",
    *SectionHeaderOffset,
    *NumberOfSections
    ));

  return Status;
}

/**
  Retrieve a pointer to and print the boot information passed by privileged
  secure firmware.

  @param  [in] SharedBufAddress   The pointer memory shared with privileged
                                  firmware.

**/
EFI_RISCV_MM_BOOT_INFO *
GetAndPrintBootinformation (
  IN VOID  *BootInfoAddress
  )
{
  EFI_RISCV_MM_BOOT_INFO        *PayloadBootInfo;
  EFI_RISCV_MM_CPU_INFO         *PayloadCpuInfo;
  UINTN                         Index;

  PayloadBootInfo = (EFI_RISCV_MM_BOOT_INFO *)BootInfoAddress;

  if (PayloadBootInfo == NULL) {
    DEBUG ((DEBUG_ERROR, "PayloadBootInfo NULL\n"));
    return NULL;
  }

  if (PayloadBootInfo->Header.Version != BOOT_PAYLOAD_VERSION) {
    DEBUG ((
      DEBUG_ERROR,
      "Boot Information Version Mismatch. Current=0x%x, Expected=0x%x.\n",
      PayloadBootInfo->Header.Version,
      BOOT_PAYLOAD_VERSION
      ));
    return NULL;
  }

  if (PayloadBootInfo->Header.Size != sizeof (EFI_RISCV_MM_BOOT_INFO)) {
    DEBUG ((
      DEBUG_ERROR,
      "Boot Information Size Mismatch. Current=%d, Expected=%d.\n",
      PayloadBootInfo->Header.Size,
      sizeof (EFI_RISCV_MM_BOOT_INFO)
      ));
    return NULL;
  }

  DEBUG ((DEBUG_INFO, "NumMmMemRegions - 0x%x\n", PayloadBootInfo->NumMmMemRegions));
  DEBUG ((DEBUG_INFO, "MmMemBase       - 0x%lx\n", PayloadBootInfo->MmMemBase));
  DEBUG ((DEBUG_INFO, "MmMemLimit      - 0x%lx\n", PayloadBootInfo->MmMemLimit));
  DEBUG ((DEBUG_INFO, "MmImageBase     - 0x%lx\n", PayloadBootInfo->MmImageBase));
  DEBUG ((DEBUG_INFO, "MmStackBase     - 0x%lx\n", PayloadBootInfo->MmStackBase));
  DEBUG ((DEBUG_INFO, "MmHeapBase      - 0x%lx\n", PayloadBootInfo->MmHeapBase));
  DEBUG ((DEBUG_INFO, "MmNsCommBufBase - 0x%lx\n", PayloadBootInfo->MmNsCommBufBase));
  DEBUG ((DEBUG_INFO, "MmSharedBufBase - 0x%lx\n", PayloadBootInfo->MmSharedBufBase));

  DEBUG ((DEBUG_INFO, "MmImageSize     - 0x%x\n", PayloadBootInfo->MmImageSize));
  DEBUG ((DEBUG_INFO, "MmPcpuStackSize - 0x%x\n", PayloadBootInfo->MmPcpuStackSize));
  DEBUG ((DEBUG_INFO, "MmHeapSize      - 0x%x\n", PayloadBootInfo->MmHeapSize));
  DEBUG ((DEBUG_INFO, "MmNsCommBufSize - 0x%x\n", PayloadBootInfo->MmNsCommBufSize));
  DEBUG ((DEBUG_INFO, "MmSharedBufSize - 0x%x\n", PayloadBootInfo->MmSharedBufSize));

  DEBUG ((DEBUG_INFO, "NumCpus         - 0x%x\n", PayloadBootInfo->NumCpus));

  PayloadCpuInfo = (EFI_RISCV_MM_CPU_INFO *)&(PayloadBootInfo->CpuInfo);

  for (Index = 0; Index < PayloadBootInfo->NumCpus; Index++) {
    DEBUG ((DEBUG_INFO, "ProcessorId        - 0x%lx\n", PayloadCpuInfo[Index].ProcessorId));
    DEBUG ((DEBUG_INFO, "Package            - 0x%x\n", PayloadCpuInfo[Index].Package));
    DEBUG ((DEBUG_INFO, "Core               - 0x%x\n", PayloadCpuInfo[Index].Core));
  }

  return PayloadBootInfo;
}

/**
  A loop to delegated events.

  @param  [in] EventCompleteSvcArgs   Pointer to the event completion arguments.

**/
VOID
EFIAPI
DelegatedEventLoop (IN UINTN CpuId, IN UINT64 MmNsCommBufBase)
{
  EFI_STATUS  Status;

  ASSERT (((EFI_MM_COMMUNICATE_HEADER *)MmNsCommBufBase)->MessageLength == 0);

  while (TRUE) {
    CpuSleep ();
    Status = CpuDriverEntryPoint (0, CpuId, MmNsCommBufBase);
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "Failed delegated Status 0x%x\n",
        Status
        ));
    }
  }
}

/**
  The entry point of Standalone MM Foundation.

  @param  [in]  CpuId             The Id assigned to this running CPU
  @param  [in]  BootInfoAddress   The address of boot info

**/
VOID
EFIAPI
CModuleEntryPoint (
  IN UINT64  CpuId,
  IN VOID    *BootInfoAddress
  )
{
  EFI_RISCV_MM_BOOT_INFO          *PayloadBootInfo;
  VOID                            *HobStart;
  PE_COFF_LOADER_IMAGE_CONTEXT    ImageContext;
  EFI_STATUS                      Status;
  UINT32                          SectionHeaderOffset;
  UINT16                          NumberOfSections;
  VOID                            *TeData;
  UINTN                           TeDataSize;
  EFI_PHYSICAL_ADDRESS            ImageBase;

  PayloadBootInfo = GetAndPrintBootinformation (BootInfoAddress);
  if (PayloadBootInfo == NULL) {
    return;
  }

  if ((PayloadBootInfo->Header.Attr | EFI_PARAM_ATTR_APTEE) != 0) {
    //
    // Register shared memory
    //
    SbiTeeGuestShareMemoryRegion (PayloadBootInfo->MmNsCommBufBase, PayloadBootInfo->MmNsCommBufSize);
  }

  // Locate PE/COFF File information for the Standalone MM core module
  Status = LocateStandaloneMmCorePeCoffData (
             (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)PayloadBootInfo->MmImageBase,
             &TeData,
             &TeDataSize
             );

  if (EFI_ERROR (Status)) {
    return;
  }

  // Obtain the PE/COFF Section information for the Standalone MM core module
  Status = GetStandaloneMmCorePeCoffSections (
             TeData,
             &ImageContext,
             &ImageBase,
             &SectionHeaderOffset,
             &NumberOfSections
             );

  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // ImageBase may deviate from ImageContext.ImageAddress if we are dealing
  // with a TE image, in which case the latter points to the actual offset
  // of the image, whereas ImageBase refers to the address where the image
  // would start if the stripped PE headers were still in place. In either
  // case, we need to fix up ImageBase so it refers to the actual current
  // load address.
  //
  ImageBase += (UINTN)TeData - ImageContext.ImageAddress;

  if (ImageContext.ImageAddress != (UINTN)TeData) {
    ImageContext.ImageAddress = (UINTN)TeData;
    Status = PeCoffLoaderRelocateImage (&ImageContext);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Create Hoblist based upon boot information passed by privileged software
  //
  HobStart = CreateHobListFromBootInfo (&CpuDriverEntryPoint, PayloadBootInfo);

  //
  // Call the MM Core entry point
  //
  ProcessModuleEntryPointList (HobStart);

  DEBUG ((DEBUG_INFO, "Cpu Driver EP %p\n", (VOID *)CpuDriverEntryPoint));

  DelegatedEventLoop (CpuId, PayloadBootInfo->MmNsCommBufBase + sizeof (EFI_MMRAM_DESCRIPTOR));
}
