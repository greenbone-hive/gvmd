/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "asset_credential_partition.h"
#include <string.h>

static int
same_string (const char *left, const char *right)
{
  if (left == NULL || right == NULL)
    return left == right;
  return strcmp (left, right) == 0;
}

static int
same_route (const acr_host_route_t *left, const acr_host_route_t *right)
{
  size_t service;
  if (!same_string (left->source_target_id, right->source_target_id))
    return 0;
  for (service = 0; service < ACR_SERVICE_COUNT; ++service)
    if (!same_string (left->credentials[service], right->credentials[service]))
      return 0;
  return 1;
}

acr_result_t
acr_partition_routes (const acr_host_route_t *routes, size_t count,
                      size_t *group_for_host, size_t *group_count)
{
  size_t i, j, groups = 0;
  if (routes == NULL || count == 0 || group_for_host == NULL
      || group_count == NULL)
    return ACR_INVALID_OVERRIDE;
  for (i = 0; i < count; ++i)
    {
      if (routes[i].source_target_id == NULL
          || routes[i].source_target_id[0] == '\0' || routes[i].host == NULL
          || routes[i].host[0] == '\0')
        return ACR_INVALID_OVERRIDE;
      for (j = 0; j < i; ++j)
        if (same_route (&routes[i], &routes[j]))
          break;
      if (j < i)
        group_for_host[i] = group_for_host[j];
      else
        group_for_host[i] = groups++;
    }
  *group_count = groups;
  return ACR_OK;
}
