# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Shared helpers for the docker compose e2e suite.

Replaces the former lib.sh and perf.sh. jq becomes json and socat becomes a
host side AF_UNIX client over the bind mounted kea control socket.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# Pinned client MACs mirrored by the client services in compose.yaml.
MAC_ALLOWED = "02:00:00:00:00:01"  # relayed in both phases (default action)
MAC_BLOCKED = "02:00:00:00:00:02"  # forward @blackhole in the policy phase
MAC_UNLISTED = "02:00:00:00:00:04"  # absent from the policy so denied by the fallback
MAC_REPLYDROP = "02:00:00:00:00:05"  # forwarded but its reply is dropped

E2E_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = E2E_DIR / "compose.yaml"
MACPOLICY_DIR = E2E_DIR / "macpolicy"
LINKMAP_DIR = E2E_DIR / "linkmap"
RUN_KEA_DIR = E2E_DIR / "run-kea"
KEA_SOCKET = RUN_KEA_DIR / "kea4-ctrl-socket"

# Maps a relay service to the compose profile that activates it.
PROFILE_BY_SVC = {
    "relay": "classic",
    "relay-policy": "policy",
    "relay-unnumbered": "unnumbered",
    "relay-unnumbered-giaddr": "giaddr",
    "relay-maxhops": "maxhops",
    "relay-multihomed": "multihomed",
    "relay-twoserver": "twoserver",
}

# The unnumbered relay plus the sidecar that flushes its client-net IPv4.
UNNUMBERED_SERVICES = ["relay-unnumbered", "relay-unnumbered-init"]

# Docker exit codes at or above this signal an infrastructure failure not a lease outcome.
DOCKER_INFRA_RC = 125

KEA_SOCKET_TIMEOUT = 5.0

# Shared perfdhcp client parameters. perfdhcp always emulates a relay so both legs run through ours.
PERF_IFACE = os.environ.get("PERF_IFACE", "eth0")
PERF_SERVER = os.environ.get("PERF_SERVER", "255.255.255.255")
PERF_COMMON = ["-b", "mac=02:00:ff:00:00:00", "-B", "-W", "5000000", "-l", PERF_IFACE, PERF_SERVER]


def profile_for(relay_svc: str) -> str:
    try:
        return PROFILE_BY_SVC[relay_svc]
    except KeyError:
        raise AssertionError(f"unknown relay service {relay_svc}")


class Compose:
    """Thin wrapper around docker compose scoped to the e2e compose file and one profile."""

    def __init__(self, profile: str):
        self.env = dict(os.environ, COMPOSE_PROFILES=profile)
        self._base = ["docker", "compose", "-f", str(COMPOSE_FILE)]

    def _run(self, args, *, merge=False, timeout=None):
        stderr = subprocess.STDOUT if merge else subprocess.PIPE
        return subprocess.run(
            self._base + list(args),
            cwd=E2E_DIR,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=stderr,
            timeout=timeout,
        )

    def up(self, *services, build=True):
        args = ["up"]
        if build:
            args.append("--build")
        args += ["-d", *services]
        proc = self._run(args, merge=True, timeout=600)
        if proc.returncode != 0:
            raise AssertionError(f"compose up failed:\n{_text(proc.stdout)}")

    def build(self, service):
        proc = self._run(["build", service], merge=True, timeout=600)
        if proc.returncode != 0:
            raise AssertionError(f"compose build {service} failed:\n{_text(proc.stdout)}")

    def logs(self, service) -> str:
        return _text(self._run(["logs", "--no-color", service]).stdout)

    def run(self, service, *args, timeout=180):
        """Runs a one-off service (client or perfdhcp). Returns (rc, combined output)."""
        proc = self._run(["run", "--rm", "--no-deps", service, *args], merge=True, timeout=timeout)
        return proc.returncode, _text(proc.stdout)

    def down(self):
        self._run(["down", "-v", "--remove-orphans"], merge=True, timeout=120)


def _text(raw: bytes | None) -> str:
    # Packet debug can emit non utf8 bytes so decode leniently the way grep -a did.
    return (raw or b"").decode("utf-8", "replace")


def _tail(text: str, n: int = 20) -> str:
    return "\n".join(text.splitlines()[-n:])


def log(msg: str) -> None:
    # Step banner mirroring the shell echo lines. Flushed so it orders correctly under -s.
    print(f"=== {msg} ===", flush=True)


# Kea control socket dialogue. Replaces socat plus jq.
def kea_cmd(cmd: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(KEA_SOCKET_TIMEOUT)
        sock.connect(str(KEA_SOCKET))
        sock.sendall(json.dumps(cmd).encode())
        return _recv_json(sock)


def _recv_json(sock: socket.socket) -> dict:
    # Read until the accumulated bytes parse. Kea may hold the connection so do not wait for EOF.
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        try:
            return json.loads(buf)
        except json.JSONDecodeError:
            continue
    if not buf:
        raise RuntimeError("kea control socket closed or timed out with no reply")
    return json.loads(buf)


def kea_stat(name: str) -> int:
    reply = kea_cmd({"command": "statistic-get", "arguments": {"name": name}})
    try:
        value = reply["arguments"][name][0][0]
    except KeyError, IndexError, TypeError:
        return 0
    try:
        return int(value)
    except TypeError, ValueError:
        return 0


def lease_count() -> int:
    reply = kea_cmd({"command": "lease4-get-all", "arguments": {"subnets": [1]}})
    if reply.get("result") != 0:
        return 0
    return len(reply.get("arguments", {}).get("leases", []))


def leases_for(mac: str) -> tuple[int, list]:
    """Returns the kea result code and the lease list for a MAC."""
    reply = kea_cmd({"command": "lease4-get-by-hw-address", "arguments": {"hw-address": mac}})
    return reply.get("result"), reply.get("arguments", {}).get("leases", [])


def circuit_id_hex(ifindex: str) -> str:
    # Agent Circuit ID sub option for an ifIndex encoded as ASCII (sub option 1).
    return "01" + format(len(ifindex), "02x") + ifindex.encode().hex()


def step_summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(md)
    else:
        print(md, end="")


@dataclass
class Stack:
    """A brought up relay plus kea, bound to one relay service."""

    compose: Compose
    relay_svc: str

    def relay_logs(self) -> str:
        return self.compose.logs(self.relay_svc)

    def _log_fail(self, msg: str) -> str:
        return f"{msg}\n--- last relay log lines ---\n{_tail(self.relay_logs())}"

    def wait_log(self, needle: str, msg: str) -> None:
        _wait(lambda: needle in self.relay_logs(), lambda: self._log_fail(msg))

    def wait_log_re(self, pattern: str, msg: str) -> None:
        rx = re.compile(pattern)
        _wait(lambda: rx.search(self.relay_logs()) is not None, lambda: self._log_fail(msg))

    def wait_service_log(self, service: str, needle: str, msg: str) -> None:
        def fail() -> str:
            logs = self.compose.logs(service)
            return f"{msg}\n--- {service} logs ---\n{_tail(logs)}"

        _wait(lambda: needle in self.compose.logs(service), fail)

    def relay_ready(self) -> None:
        self.wait_log("DHCPv4-Relay version:", f"{self.relay_svc} did not become ready")

    def kea_ready(self) -> None:
        for _ in range(60):
            try:
                if kea_cmd({"command": "version-get"}).get("result") == 0:
                    return
            except OSError, json.JSONDecodeError:
                pass
            time.sleep(0.5)
        raise AssertionError("kea control socket never became ready")

    def kea_reset_stats(self) -> None:
        kea_cmd({"command": "statistic-reset-all"})
        kea_cmd({"command": "lease4-wipe"})

    def kea_stat(self, name: str) -> int:
        return kea_stat(name)

    def expect_lease(self, service: str) -> None:
        rc, out = self.compose.run(
            service, "-i", "eth0", "-t", "3", "-T", "2", "-A", "0", "-q", "-n", "-f", "-s", "/bin/true"
        )
        if rc != 0:
            raise AssertionError(f"{service} did not get a lease (rc={rc})\n{out}")

    def expect_no_lease(self, service: str, msg: str) -> None:
        rc, out = self.compose.run(
            service, "-i", "eth0", "-t", "2", "-T", "2", "-A", "0", "-q", "-n", "-f", "-s", "/bin/true"
        )
        if rc >= DOCKER_INFRA_RC:
            raise AssertionError(f"{service} container did not run (rc={rc})\n{out}")
        if rc == 0:
            raise AssertionError(msg)

    def assert_lease(self, mac: str, msg: str) -> None:
        result, leases = leases_for(mac)
        if result != 0 or len(leases) == 0:
            raise AssertionError(f"{msg} (no kea lease for {mac})")

    def assert_no_lease(self, mac: str, msg: str) -> None:
        result, leases = leases_for(mac)
        if not (result == 3 or len(leases) == 0):
            raise AssertionError(f"{msg} (kea has a lease for {mac})")

    def assert_lease_count(self, want: int, msg: str) -> None:
        got = lease_count()
        if got != want:
            raise AssertionError(f"{msg} (leases={got} want {want})")

    def assert_lease_opt82(self, mac: str, msg: str) -> None:
        # Find the ingress ifIndex the relay logged for this MAC then confirm the lease carries its circuit id.
        matches = [line for line in self.relay_logs().splitlines() if mac in line]
        m = re.search(r"IfIndex=(\d+)", matches[-1]) if matches else None
        if m is None:
            last = matches[-1] if matches else "<none>"
            raise AssertionError(f"{msg} (no IfIndex logged for {mac}); last relay line: {last}")
        want = circuit_id_hex(m.group(1))
        _, leases = leases_for(mac)
        user_context = leases[0].get("user-context", {}) if leases else {}
        got = json.dumps(user_context, separators=(",", ":")).lower().replace(" ", "")
        if want not in got:
            raise AssertionError(f"{msg} (circuit-id {want} absent from user-context {got})")

    def kea_report(self, title: str) -> None:
        if not title:
            return
        rows = [
            "pkt4-received",
            "pkt4-discover-received",
            "pkt4-offer-sent",
            "pkt4-request-received",
            "pkt4-ack-sent",
            "pkt4-nak-sent",
        ]
        lines = [f"### Kea view: {title}", "", "| Metric | Value |", "|---|---|"]
        lines += [f"| {name} | {kea_stat(name)} |" for name in rows]
        lines.append(f"| leases | {lease_count()} |")
        step_summary("\n".join(lines) + "\n\n")


def _wait(check, on_fail, tries: int = 30, delay: float = 0.5) -> None:
    for _ in range(tries):
        if check():
            return
        time.sleep(delay)
    raise AssertionError(on_fail())


# perfdhcp report parsing. Replaces the awk field extraction in perf.sh.
def perf_field(text: str, pattern: str):
    rx = re.compile(pattern)
    for line in text.splitlines():
        if rx.search(line):
            return line.split()[-1]
    return None


def perf_drops(text: str) -> int:
    # Sum drops across both exchange stages so a loss in either DISCOVER-OFFER or REQUEST-ACK counts.
    total = 0
    for line in text.splitlines():
        if re.match(r"\s*drops:", line):
            try:
                total += int(line.split()[-1])
            except ValueError:
                pass
    return total


def perf_avg_delay(text: str) -> str | None:
    for line in text.splitlines():
        if "avg delay:" in line:
            parts = line.split()
            if len(parts) >= 2:
                return f"{parts[-2]} {parts[-1]}"
    return None


def perf_md_row(label: str, text: str) -> str:
    sent = perf_field(text, "sent packets:")
    recv = perf_field(text, "received packets:")
    drops = perf_drops(text)
    avg = perf_avg_delay(text)
    pct = "n/a"
    if sent is not None and str(sent).isdigit() and int(sent) > 0:
        pct = f"{100 * drops / int(sent):.2f}"
    return f"| {label} | {sent or 'n/a'} | {recv or 'n/a'} | {drops} | {pct} | {avg or 'n/a'} |"


def perf_md_header() -> str:
    return "| Scenario | Sent | Received | Drops | Drop% | Avg RTT |\n|---|---|---|---|---|---|"


def assert_scenario_ok(label: str, text: str) -> None:
    sent = perf_field(text, "sent packets:")
    recv = perf_field(text, "received packets:")
    drops = perf_drops(text)
    if sent is None or recv is None or not str(sent).isdigit() or not str(recv).isdigit():
        raise AssertionError(f"{label}: could not parse perfdhcp sent/received counts\n{text}")
    sent_i, recv_i = int(sent), int(recv)
    if sent_i == 0 or recv_i != sent_i or drops != 0:
        raise AssertionError(
            f"{label}: sent={sent_i} received={recv_i} drops={drops} " "(want sent>0 and received==sent and drops==0)"
        )


def assert_kea_served(label: str) -> None:
    # Gate on kea's own view so a relay that misroutes a packet perfdhcp counts as received cannot pass.
    disc = kea_stat("pkt4-discover-received")
    ack = kea_stat("pkt4-ack-sent")
    leases = lease_count()
    if leases <= 0 or ack < leases or disc < leases:
        raise AssertionError(
            f"{label}: kea ground truth off (discover-received={disc} ack-sent={ack} leases={leases}; "
            "want leases>0 and ack-sent>=leases and discover-received>=leases)"
        )


def _atomic_write(path: Path, content: str) -> None:
    # Mirror the atomic rename the shell used so the polling relay never reads a torn file.
    path.parent.mkdir(exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)


def seed_policy(content: str) -> None:
    _atomic_write(MACPOLICY_DIR / "policy.txt", content)


def seed_linkmap(content: str) -> None:
    _atomic_write(LINKMAP_DIR / "link-map.txt", content)


@contextmanager
def bring_up(
    relay_svc: str,
    services: list[str],
    report_title: str,
    init_service: str | None = None,
    init_ready: str = "flushed client-net IPv4",
):
    """Brings up a relay plus kea, waits for readiness, resets counters, then tears it all down."""
    # Create the socket dir as the invoking user so the bind mounted socket is reachable
    # and teardown can remove it without root.
    RUN_KEA_DIR.mkdir(exist_ok=True)

    compose = Compose(profile_for(relay_svc))
    stack = Stack(compose, relay_svc)
    try:
        log(f"bringing up {' '.join(('kea', *services))}")
        compose.up("kea", *services)
        if init_service:
            stack.wait_service_log(
                init_service,
                init_ready,
                f"{init_service} never signalled ready",
            )
        stack.relay_ready()
        stack.kea_ready()
        stack.kea_reset_stats()
        log(f"{relay_svc} + kea ready, counters reset")
        yield stack
    finally:
        _teardown(stack, report_title)


def _teardown(stack: Stack, report_title: str) -> None:
    try:
        stack.kea_report(report_title)
    except Exception:
        pass
    log(f"relay logs ({stack.relay_svc})")
    print(stack.relay_logs(), flush=True)
    log("kea logs")
    print(stack.compose.logs("kea"), flush=True)
    stack.compose.down()
    for directory in (MACPOLICY_DIR, LINKMAP_DIR, RUN_KEA_DIR):
        shutil.rmtree(directory, ignore_errors=True)
