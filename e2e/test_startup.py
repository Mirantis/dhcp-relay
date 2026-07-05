# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Fail-fast startup validation. Bad config makes the relay exit non-zero before it serves."""

import shutil

from harness import LINKMAP_DIR, MACPOLICY_DIR, Compose, log, profile_for, seed_linkmap, seed_policy


def _expect_fatal(relay_svc, args, needle):
    # The relay validates config before opening sockets so a one-shot run exits non-zero at startup.
    compose = Compose(profile_for(relay_svc))
    try:
        rc, out = compose.run(relay_svc, *args, timeout=60)
        if rc == 0:
            raise AssertionError(f"{relay_svc} started instead of failing fast\n{out}")
        if needle not in out:
            raise AssertionError(f"{relay_svc} did not log the expected fatal {needle!r} (rc={rc})\n{out}")
    finally:
        compose.down()


def test_invalid_giaddr_fails_fast():
    log("invalid -giaddr aborts startup")
    _expect_fatal(
        "relay",
        ["dhcp-relay", "-dhcp-server-address=kea", "-giaddr=127.0.0.1"],
        "giaddr must be a global unicast IPv4 address",
    )


def test_malformed_policy_fails_fast():
    log("malformed initial MAC policy aborts startup")
    seed_policy("this line has too many fields to be a valid policy entry\n")
    try:
        _expect_fatal("relay-policy", [], "Error loading MAC policy")
    finally:
        shutil.rmtree(MACPOLICY_DIR, ignore_errors=True)


def test_malformed_linkmap_fails_fast():
    log("malformed initial link map aborts startup")
    seed_linkmap("not a valid link map line\n")
    try:
        _expect_fatal("relay-unnumbered", [], "Error loading link map")
    finally:
        shutil.rmtree(LINKMAP_DIR, ignore_errors=True)
