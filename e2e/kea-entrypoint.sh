#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Render the arch specific kea hooks directory into the config then run kea.
set -eu

# Kea requires the control socket directory to exist and be at most 0750.
mkdir -p /run/kea
chmod 0750 /run/kea

lease_cmds="$(find /usr/lib -name libdhcp_lease_cmds.so | head -1)"
if [ -z "${lease_cmds}" ]; then
  echo "FAIL: libdhcp_lease_cmds.so not found under /usr/lib" >&2
  exit 1
fi
hooks_dir="$(dirname "${lease_cmds}")"

sed "s#@HOOKS_DIR@#${hooks_dir}#g" /etc/kea/kea-dhcp4.conf > /run/kea/kea-dhcp4.conf

exec /usr/sbin/kea-dhcp4 -c /run/kea/kea-dhcp4.conf
