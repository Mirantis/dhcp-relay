# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""perfdhcp load benchmark for the classic and policy relays.

short is a tiny debug run with no tables and no gating. long emits the tables and
fails on any drop or kea ground-truth mismatch. Select a combination with
`-k "classic and long"`.
"""

import subprocess

import pytest

from harness import (
    PERF_COMMON,
    assert_kea_served,
    assert_scenario_ok,
    bring_up,
    kea_cmd,
    log,
    perf_md_header,
    perf_md_row,
    seed_policy,
    step_summary,
)

RELAY_DESC = {"classic": "policy-free relay", "policy": "MAC-policy relay"}
RELAY_SVC = {"classic": "relay", "policy": "relay-policy"}


def _scenarios(size):
    if size == "short":
        return [("DORA r5 N10", ["-4", "-r", "5", "-R", "10", "-n", "10"])]
    return [
        ("DORA r50 N200", ["-4", "-r", "50", "-R", "200", "-n", "200"]),
        ("DORA r100 N200", ["-4", "-r", "100", "-R", "200", "-n", "200"]),
        ("avalanche R200 r100", ["-4", "--scenario", "avalanche", "-R", "200", "-r", "100"]),
    ]


def _perfdhcp(stack, args):
    # Mirror the shell `timeout 180 docker compose run perfdhcp`. A timeout maps to rc 124.
    try:
        return stack.compose.run("perfdhcp", *args, timeout=180)
    except subprocess.TimeoutExpired as exc:
        out = (exc.output or b"").decode("utf-8", "replace")
        return 124, out + "\nERROR: perfdhcp timed out after 180s"


@pytest.mark.parametrize("size", ["short", "long"])
@pytest.mark.parametrize("mode", ["classic", "policy"])
def test_bench(mode, size):
    if mode == "policy":
        seed_policy("* @default\n")

    svc = RELAY_SVC[mode]
    title = RELAY_DESC[mode] if size == "long" else ""

    with bring_up(svc, [svc], title) as stack:
        stack.compose.build("perfdhcp")

        rows = []
        failures = []
        for label, args in _scenarios(size):
            # result 0 wiped leases and result 3 is kea's empty code. Both mean the subnet is clear.
            reply = kea_cmd({"command": "lease4-wipe", "arguments": {"subnet-id": 1}})
            assert reply.get("result") in (0, 3), f"lease4-wipe failed for {label}"
            stack.kea_reset_stats()

            log(f"benchmark {mode} {size}: {label}")
            rc, out = _perfdhcp(stack, args + PERF_COMMON)
            # Stream the perfdhcp report the way the shell tee did so short debug runs stay visible.
            print(out, flush=True)

            if rc != 0:
                print(f"WARN: perfdhcp failed (rc={rc}) for {label}", flush=True)
                if size == "long":
                    rows.append(perf_md_row(f"{label} [FAILED]", out))
                    failures.append(f"{label}: perfdhcp exited rc={rc}")
                continue

            if size == "long":
                rows.append(perf_md_row(label, out))
                for check in (lambda: assert_scenario_ok(label, out), lambda: assert_kea_served(label)):
                    try:
                        check()
                    except AssertionError as exc:
                        failures.append(str(exc))

        if size == "long":
            table = "\n".join([f"### Benchmark: {RELAY_DESC[mode]}", "", perf_md_header(), *rows])
            step_summary(table + "\n\n")

        # long gates on delivery. short is debug only so it never gates.
        assert not failures, "; ".join(failures)
