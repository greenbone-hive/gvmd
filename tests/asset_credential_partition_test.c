/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../src/asset_credential_partition.h"
#include <assert.h>

int
main (void)
{
  acr_host_route_t routes[6] = {
    {"target-a", "host-1", {"B", 0, "SMB-B"}},
    {"target-a", "host-2", {"B", 0, "SMB-B"}},
    {"target-a", "host-3", {"B", 0, "SMB-B"}},
    {"target-b", "host-4", {"B", 0, "SMB-B"}},
    {"target-b", "host-5", {"B", 0, "SMB-B"}},
    {"target-b", "host-6", {"B", 0, "SMB-B"}},
  };
  size_t groups[6], count;

  assert (acr_partition_routes (routes, 6, groups, &count) == ACR_OK);
  assert (count == 2);
  assert (groups[0] == 0 && groups[1] == 0 && groups[2] == 0);
  assert (groups[3] == 1 && groups[4] == 1 && groups[5] == 1);

  routes[2].credentials[ACR_SSH] = "A";
  assert (acr_partition_routes (routes, 6, groups, &count) == ACR_OK);
  assert (count == 3);
  assert (groups[0] == groups[1] && groups[2] != groups[0]);
  assert (groups[3] == groups[4] && groups[4] == groups[5]);

  routes[2].credentials[ACR_SSH] = "B";
  routes[2].credentials[ACR_SMB] = "SMB-A";
  assert (acr_partition_routes (routes, 6, groups, &count) == ACR_OK);
  assert (count == 3);
  assert (groups[2] != groups[0]);

  assert (acr_partition_routes (NULL, 6, groups, &count)
          == ACR_INVALID_OVERRIDE);
  return 0;
}
