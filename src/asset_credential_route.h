/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef ASSET_CREDENTIAL_ROUTE_H
#define ASSET_CREDENTIAL_ROUTE_H
#include <stddef.h>

typedef enum
{
  ACR_SSH = 0,
  ACR_SMB,
  ACR_ESXI,
  ACR_SNMP,
  ACR_KRB5,
  ACR_SSH_ELEVATE,
  ACR_SERVICE_COUNT
} acr_service_t;

typedef struct
{
  acr_service_t service;
  const char *credential_id;
} acr_override_t;

typedef enum
{
  ACR_OK = 0,
  ACR_AMBIGUOUS_ASSET,
  ACR_INVALID_OVERRIDE,
  ACR_DUPLICATE_OVERRIDE
} acr_result_t;

/* Resolve credential references for exactly one concrete host. The caller
 * must first resolve target host text to assets in the same owner scope.
 * Output pointers borrow storage from defaults/overrides; no secrets flow. */
acr_result_t acr_resolve (const char *const defaults[ACR_SERVICE_COUNT],
                          size_t matching_assets,
                          const acr_override_t *overrides,
                          size_t override_count,
                          const char *effective[ACR_SERVICE_COUNT]);
#endif
