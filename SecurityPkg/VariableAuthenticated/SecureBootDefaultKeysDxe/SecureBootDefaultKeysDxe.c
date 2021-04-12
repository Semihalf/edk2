/** @file
  This driver init default Secure Boot variables

Copyright (c) 2021, ARM Ltd. All rights reserved.<BR>
Copyright (c) 2021, Semihalf All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/SecureBootVariableLib.h>

/**
  The entry point for SecureBootDefaultKeys driver.

  @param[in]  ImageHandle        The image handle of the driver.
  @param[in]  SystemTable        The system table.

  @retval EFI_ALREADY_STARTED    The driver already exists in system.
  @retval EFI_OUT_OF_RESOURCES   Fail to execute entry point due to lack of resources.
  @retval EFI_SUCCESS            All the related protocols are installed on the driver.
  @retval Others                 Fail to get the SecureBootEnable variable.

**/
EFI_STATUS
EFIAPI
SecureBootDefaultKeysEntryPoint (
  IN EFI_HANDLE          ImageHandle,
  IN EFI_SYSTEM_TABLE    *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = SecureBootInitPKDefault ();
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "%a: Cannot initialize PKDefault: %r\n", __FUNCTION__, Status));
    return Status;
  }

  Status = SecureBootInitKEKDefault ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Cannot initialize KEKDefault: %r\n", __FUNCTION__, Status));
    return Status;
  }
  Status = SecureBootInitdbDefault ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Cannot initialize dbDefault: %r\n", __FUNCTION__, Status));
    return Status;
  }

  Status = SecureBootInitdbtDefault ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: dbtDefault not initialized\n", __FUNCTION__));
  }

  Status = SecureBootInitdbxDefault ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: dbxDefault not initialized\n", __FUNCTION__));
  }

  return Status;
}
