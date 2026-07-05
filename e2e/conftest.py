# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""pytest fixtures for the e2e suite.

Each phase fixture brings up its relay plus kea, waits for readiness, resets kea
counters, then tears the stack down. Replaces the per script setup and trap cleanup.
"""

from __future__ import annotations

import pytest

from harness import UNNUMBERED_SERVICES, bring_up, seed_linkmap, seed_policy


@pytest.fixture(scope="module")
def classic_stack():
    with bring_up("relay", ["relay"], "functional: policy-free relay (every client relayed)") as stack:
        yield stack


@pytest.fixture(scope="module")
def policy_stack():
    # Strict allow-list with no catch-all. MAC 02:00:00:00:00:04 is absent so it hits the fallback blackhole.
    seed_policy(
        "# e2e MAC policy (phase 2)\n"
        "02:00:00:00:00:01                       # default action relays via kea\n"
        "02:00:00:00:00:02 @blackhole            # forward dropped\n"
        "02:00:00:00:00:05 @default @blackhole   # forward ok but reply dropped\n"
        "# 02:00:00:00:00:04 absent so it hits the fallback blackhole\n"
    )
    title = "functional: MAC-policy relay (per-client decisions + hot reload)"
    with bring_up("relay-policy", ["relay-policy"], title) as stack:
        yield stack


@pytest.fixture(scope="module")
def unnumbered_stack():
    seed_linkmap("* 192.168.50.0/24\n")
    with bring_up(
        "relay-unnumbered",
        UNNUMBERED_SERVICES,
        "functional: unnumbered relay (link map + Link Selection)",
        init_service="relay-unnumbered-init",
    ) as stack:
        yield stack
