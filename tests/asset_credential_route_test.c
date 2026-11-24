/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../src/asset_credential_route.h"
#include <assert.h>
#include <string.h>

int
main (void)
{
  const char *defaults[ACR_SERVICE_COUNT] = {"B", "SMB-B", 0, 0, 0};
  const char *effective[ACR_SERVICE_COUNT];
  acr_override_t override = {ACR_SSH, "A"};
  int host;
  for (host = 1; host <= 100; ++host)
    {
      size_t count = host == 55 ? 1 : 0;
      assert (acr_resolve (defaults, count,
                           count ? &override : 0, count, effective)
              == ACR_OK);
      assert (strcmp (effective[ACR_SSH], host == 55 ? "A" : "B") == 0);
      assert (strcmp (effective[ACR_SMB], "SMB-B") == 0);
    }
  assert (acr_resolve (defaults, 2, &override, 1, effective)
          == ACR_AMBIGUOUS_ASSET);
  return 0;
}
