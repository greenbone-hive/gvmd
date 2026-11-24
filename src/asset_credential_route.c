/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "asset_credential_route.h"

acr_result_t
acr_resolve (const char *const defaults[ACR_SERVICE_COUNT],
             size_t matching_assets, const acr_override_t *overrides,
             size_t override_count,
             const char *effective[ACR_SERVICE_COUNT])
{
  size_t i;
  unsigned seen = 0;
  if (defaults == 0 || effective == 0 || (override_count && overrides == 0))
    return ACR_INVALID_OVERRIDE;
  if (matching_assets > 1)
    return ACR_AMBIGUOUS_ASSET;
  for (i = 0; i < ACR_SERVICE_COUNT; ++i)
    effective[i] = defaults[i];
  if (matching_assets == 0)
    return override_count == 0 ? ACR_OK : ACR_INVALID_OVERRIDE;
  for (i = 0; i < override_count; ++i)
    {
      unsigned bit;
      if (overrides[i].service < 0
          || overrides[i].service >= ACR_SERVICE_COUNT
          || overrides[i].credential_id == 0
          || overrides[i].credential_id[0] == '\0')
        return ACR_INVALID_OVERRIDE;
      bit = 1u << overrides[i].service;
      if (seen & bit)
        return ACR_DUPLICATE_OVERRIDE;
      seen |= bit;
      effective[overrides[i].service] = overrides[i].credential_id;
    }
  return ACR_OK;
}
