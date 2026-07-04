#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Render the arch specific kea hooks directory into the config then run kea.
set -eu

# Kea requires the control socket directory to exist and be at most 0750.
mkdir -p /run/kea
chmod 0750 /run/kea

lease_cmds="$(find /usr/lib -name libdhcp_lease_cmds.so -type f)"
if [ -z "${lease_cmds}" ]; then
  echo "FAIL: libdhcp_lease_cmds.so not found under /usr/lib" >&2
  exit 1
fi
lease_count=$(printf '%s\n' "${lease_cmds}" | grep -c .)
if [ "${lease_count}" -gt 1 ]; then
  echo "FAIL: multiple libdhcp_lease_cmds.so found, expected exactly one:" >&2
  printf '%s\n' "${lease_cmds}" >&2
  exit 1
fi
lease_cmds=$(printf '%s\n' "${lease_cmds}" | head -1)
hooks_dir="$(dirname "${lease_cmds}")"

sed "s#@HOOKS_DIR@#${hooks_dir}#g" /etc/kea/kea-dhcp4.conf > /run/kea/kea-dhcp4.conf
chmod 0640 /run/kea/kea-dhcp4.conf

exec /usr/sbin/kea-dhcp4 -c /run/kea/kea-dhcp4.conf
