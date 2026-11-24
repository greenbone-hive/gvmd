/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef ASSET_CREDENTIAL_PARTITION_H
#define ASSET_CREDENTIAL_PARTITION_H

#include "asset_credential_route.h"
#include <stddef.h>

/* One already-resolved host. Credential references are IDs, not secrets. */
typedef struct
{
  const char *source_target_id;
  const char *host;
  const char *credentials[ACR_SERVICE_COUNT];
} acr_host_route_t;

/* Group hosts only when source target and the entire effective credential
 * vector match. Group numbers follow first occurrence and are written to
 * group_for_host. The caller retains ownership of all strings and arrays. */
acr_result_t acr_partition_routes (const acr_host_route_t *routes, size_t count,
                                   size_t *group_for_host,
                                   size_t *group_count);

#endif
