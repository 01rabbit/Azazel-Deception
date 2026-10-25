#!/usr/bin/env python3
"""SO-08 virtual-lab drift-injection harness (CI regression signal, NOT a gate).

SO-08 (Azazel-Deception#41): *detect isolation drift within 2 s and withdraw
attacker-route exposure within 5 s, independent of runtime cleanup.* Its
release class is **hardware-only**. This harness builds the topology out of
Linux network/PID namespaces instead of a real segment, so what it produces is
a ``virtual-lab-regression`` record with ``gate: false``. **No run of this
harness, green or otherwise, satisfies the HIL gate** — see
``docs/so08-isolation-drift.md`` and ``azazel_deception.runtime.so08_record``.

What it does, per declared drift kind
(``azazel_deception.runtime.isolation_drift.DRIFT_KINDS``), 20 times:

1. **inject** the drift and take ``start`` on the harness host's monotonic
   clock *before* issuing the injection, so the latency can only be
   over-stated, never under-stated;
2. let AZ-06's ``IsolationDriftObserver`` — fed by a procfs sampler polling
   the namespaces — record it into AZ-06's real evidence chain
   (``RuntimeStateStore.append_evidence``);
3. take ``end(detect)`` when the harness reads that record back out of the
   evidence-chain file;
4. run the **active reachability probe** (a TCP connect from the decoy
   namespace to the protected host) once, to record whether the drift actually
   exposed the protected side — descriptive only;
5. revert its own injection and wait for the observer to see it gone.

What it does **not** do: withdraw anything on Deception's behalf. Withdrawal is
enforcement and belongs to Azazel-Edge's authority path, which Edge has not
declared (Azazel-Edge#412). The withdrawal half is therefore recorded as
``not_measurable`` with that gap, and the overall verdict is never ``pass``.
Step 5 is the harness undoing its own fixture after the sample is taken; it is
not timed, not reported as withdrawal, and not reachable from AZ-06 code.

Exit status — the harness never turns a run it could not do into green:

* ``0`` — every sample executed and every detection sample was within 2 s.
  The record's verdict is still ``not_measurable`` and ``gate`` is false.
* ``1`` — the run executed and the detection half regressed.
* ``2`` — the run did not execute (not Linux, not root, a missing tool,
  namespaces refused, a precondition failed). A record with
  ``executed: false`` and ``verdict: not_measurable`` is still written.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from azazel_deception.runtime import so08_record as rec  # noqa: E402
from azazel_deception.runtime.isolation_drift import (  # noqa: E402
    DRIFT_KINDS,
    IsolationDriftObserver,
    recorded_drift,
)
from azazel_deception.runtime.state import RuntimeStateStore  # noqa: E402

EXIT_DETECTION_WITHIN_BOUND = 0
EXIT_DETECTION_REGRESSION = 1
EXIT_NOT_EXECUTED = 2

HARNESS_VERSION = "1"
POLL_INTERVAL_S = 0.05  # detector sampling period
READBACK_INTERVAL_S = 0.005  # harness evidence-chain read-back period
SAMPLE_TIMEOUT_S = 10.0  # an undetected sample is recorded unfinished, not dropped
SETTLE_TIMEOUT_S = 10.0

ENVIRONMENT_ID = "so08-virtual-lab"
PACKAGE_ID = "municipal-linux-v1"
NODE_ID = "so08-virtual-lab-node"

DEFAULT_OUTPUT = ROOT / "artifacts/so08/so08-virtual-lab.json"


class LabUnavailable(RuntimeError):
    """The lab could not be built; the run did not execute."""


class Lab(Protocol):
    backend: str

    def describe(self) -> dict[str, Any]: ...
    def setup(self) -> None: ...
    def teardown(self) -> None: ...
    def sample(self) -> dict[str, frozenset[str]]: ...
    def inject(self, kind: str) -> Any: ...
    def revert(self, kind: str, handle: Any) -> None: ...
    def probe(self) -> bool: ...
    def control_probe(self) -> bool: ...


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=30)


_LISTENER = (
    "import socket,time\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "s.bind(({host!r},{port}))\n"
    "s.listen(16)\n"
    "while True:\n"
    "    c,_=s.accept()\n"
    "    c.close()\n"
)

_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    socket.create_connection(({host!r},{port}),timeout={timeout}).close()\n"
    "except OSError:\n"
    "    sys.exit(1)\n"
    "sys.exit(0)\n"
)


def _hex_le_to_ip(value: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(value, 16)))


class NamespaceLab:
    """decoy <-> router <-> protected, plus a front (publish-side) namespace.

    * ``decoy``: the decoy workload, a non-root process with every capability
      dropped (``setpriv``) in its own PID namespace. Its routing table holds
      only its connected /24 — no route to the protected network.
    * ``router``: forwards between the decoy and protected links. Isolation
      is the decoy's lack of a route, which is exactly what route drift
      breaks.
    * ``protected``: the protected network, with a TCP listener the probe
      tries to reach.
    * ``front``: where a published port would appear (the analogue of the
      host side of a Compose port mapping). It has no listener at baseline.
    """

    backend = rec.VIRTUAL_LAB_BACKEND

    PREFIX = "azs08"
    DECOY_NET = ipaddress.ip_network("10.208.1.0/24")
    PROTECTED_NET = ipaddress.ip_network("10.208.2.0/24")
    DECOY_ADDR = "10.208.1.2"
    ROUTER_DECOY_ADDR = "10.208.1.1"
    ROUTER_PROTECTED_ADDR = "10.208.2.1"
    PROTECTED_ADDR = "10.208.2.2"
    PROTECTED_PORT = 8007
    PUBLISH_PORT = 18080

    REQUIRED_TOOLS = ("ip", "unshare", "nsenter", "setpriv", "sleep")

    def __init__(self) -> None:
        p = self.PREFIX
        self.ns = {name: f"{p}-{name}" for name in ("decoy", "router", "protected", "front")}
        self._procs: list[subprocess.Popen[str]] = []
        self.decoy_pid: int | None = None
        self.decoy_pidns: str | None = None
        self.front_pid: int | None = None

    # -- description --------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "namespaces": dict(self.ns),
            "decoy_network": str(self.DECOY_NET),
            "protected_network": str(self.PROTECTED_NET),
            "probe_target": f"{self.PROTECTED_ADDR}:{self.PROTECTED_PORT}/tcp",
            "decoy_workload": "uid 65534, setpriv --inh-caps=-all --bounding-set=-all "
            "--no-new-privs, own PID namespace",
            "injections": {
                "route_to_protected": f"ip route add {self.PROTECTED_NET} via "
                f"{self.ROUTER_DECOY_ADDR} in the decoy namespace",
                "published_port": f"a TCP listener on 0.0.0.0:{self.PUBLISH_PORT} appears in "
                "the front namespace (host side of a port mapping)",
                "capability_regranted": "a root process joins the decoy's PID and network "
                "namespaces with a full capability set (the analogue of `docker exec "
                "--privileged`)",
            },
            "samplers": {
                "route_to_protected": "/proc/<decoy pid>/net/route, any route overlapping "
                "the protected network",
                "published_port": "/proc/<front pid>/net/tcp{,6}, any socket in LISTEN",
                "capability_regranted": "/proc/*/status CapEff of every process in the "
                "decoy PID namespace, any non-zero set",
            },
        }

    # -- lifecycle ----------------------------------------------------------
    def preflight(self) -> None:
        if not sys.platform.startswith("linux"):
            raise LabUnavailable(f"not Linux ({sys.platform}); namespaces are unavailable")
        if os.geteuid() != 0:
            raise LabUnavailable("not root; creating network namespaces needs CAP_SYS_ADMIN")
        missing = [tool for tool in self.REQUIRED_TOOLS if shutil.which(tool) is None]
        if missing:
            raise LabUnavailable(f"required tools are missing: {missing}")

    def setup(self) -> None:
        self.preflight()
        self._delete_namespaces()
        ns = self.ns
        p = self.PREFIX
        try:
            for name in ns.values():
                _run("ip", "netns", "add", name)
            _run("ip", "link", "add", f"{p}-d0", "type", "veth", "peer", "name", f"{p}-d1")
            _run("ip", "link", "set", f"{p}-d0", "netns", ns["decoy"])
            _run("ip", "link", "set", f"{p}-d1", "netns", ns["router"])
            _run("ip", "link", "add", f"{p}-p0", "type", "veth", "peer", "name", f"{p}-p1")
            _run("ip", "link", "set", f"{p}-p0", "netns", ns["protected"])
            _run("ip", "link", "set", f"{p}-p1", "netns", ns["router"])
            for name in ns.values():
                _run("ip", "-n", name, "link", "set", "lo", "up")
            _run("ip", "-n", ns["decoy"], "addr", "add", f"{self.DECOY_ADDR}/24", "dev", f"{p}-d0")
            _run("ip", "-n", ns["decoy"], "link", "set", f"{p}-d0", "up")
            _run("ip", "-n", ns["router"], "addr", "add", f"{self.ROUTER_DECOY_ADDR}/24",
                 "dev", f"{p}-d1")
            _run("ip", "-n", ns["router"], "addr", "add", f"{self.ROUTER_PROTECTED_ADDR}/24",
                 "dev", f"{p}-p1")
            _run("ip", "-n", ns["router"], "link", "set", f"{p}-d1", "up")
            _run("ip", "-n", ns["router"], "link", "set", f"{p}-p1", "up")
            _run("ip", "netns", "exec", ns["router"], "sh", "-c",
                 "echo 1 > /proc/sys/net/ipv4/ip_forward")
            _run("ip", "-n", ns["protected"], "addr", "add", f"{self.PROTECTED_ADDR}/24",
                 "dev", f"{p}-p0")
            _run("ip", "-n", ns["protected"], "link", "set", f"{p}-p0", "up")
            _run("ip", "-n", ns["protected"], "route", "add", "default", "via",
                 self.ROUTER_PROTECTED_ADDR)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            raise LabUnavailable(f"namespace setup refused: {detail.strip()}") from exc

        listener = _LISTENER.format(host=self.PROTECTED_ADDR, port=self.PROTECTED_PORT)
        self._spawn("ip", "netns", "exec", ns["protected"], sys.executable, "-c", listener)
        front = self._spawn("ip", "netns", "exec", ns["front"], "sleep", "infinity")
        self.front_pid = front.pid
        decoy = self._spawn(
            "ip", "netns", "exec", ns["decoy"],
            "unshare", "--pid", "--fork", "--mount-proc",
            "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
            "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs",
            "sleep", "infinity",
        )
        self.decoy_pid = self._wait_for_child_with_dropped_caps(decoy.pid)
        self.decoy_pidns = os.readlink(f"/proc/{self.decoy_pid}/ns/pid")
        if not self._wait(lambda: self.control_probe(), SETTLE_TIMEOUT_S):
            raise LabUnavailable("protected listener never became reachable from the router")

    def teardown(self) -> None:
        for proc in reversed(self._procs):
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._procs.clear()
        self._delete_namespaces()

    def _delete_namespaces(self) -> None:
        for name in self.ns.values():
            _run("ip", "netns", "del", name, check=False)

    def _spawn(self, *args: str) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True
        )
        self._procs.append(proc)
        return proc

    @staticmethod
    def _wait(predicate: Any, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return True
            except OSError:
                pass
            time.sleep(0.02)
        return False

    @staticmethod
    def _children(pid: int) -> list[int]:
        out = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
            except OSError:
                continue
            fields = stat[stat.rfind(")") + 2 :].split()
            if int(fields[1]) == pid:
                out.append(int(entry.name))
        return out

    def _wait_for_child_with_dropped_caps(self, unshare_pid: int) -> int:
        found: list[int] = []

        def ready() -> bool:
            for child in self._children(unshare_pid):
                status = Path(f"/proc/{child}/status").read_text()
                fields = dict(
                    line.split(":\t", 1) for line in status.splitlines() if ":\t" in line
                )
                if fields.get("Name", "").strip() == "sleep" and int(fields["CapEff"], 16) == 0:
                    found.append(child)
                    return True
            return False

        if not self._wait(ready, SETTLE_TIMEOUT_S):
            raise LabUnavailable("decoy workload never reached a dropped-capability state")
        return found[0]

    # -- sampling (observation only; procfs reads, no process joins the decoy) --
    def sample(self) -> dict[str, frozenset[str]]:
        return {
            "route_to_protected": self._routes_to_protected(),
            "published_port": self._front_listeners(),
            "capability_regranted": self._decoy_capabilities(),
        }

    def _routes_to_protected(self) -> frozenset[str]:
        lines = Path(f"/proc/{self.decoy_pid}/net/route").read_text().splitlines()[1:]
        findings = set()
        for line in lines:
            fields = line.split()
            if len(fields) < 8:
                continue
            iface, dest, gateway, mask = fields[0], fields[1], fields[2], fields[7]
            network = ipaddress.ip_network(
                f"{_hex_le_to_ip(dest)}/{_hex_le_to_ip(mask)}", strict=False
            )
            if network.overlaps(self.PROTECTED_NET):
                findings.add(f"{iface}:{network}:via:{_hex_le_to_ip(gateway)}")
        return frozenset(findings)

    def _front_listeners(self) -> frozenset[str]:
        findings = set()
        for table in ("tcp", "tcp6"):
            path = Path(f"/proc/{self.front_pid}/net/{table}")
            if not path.exists():
                continue
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and fields[3] == "0A":  # TCP_LISTEN
                    port = int(fields[1].rsplit(":", 1)[1], 16)
                    findings.add(f"{table}:{port}")
        return frozenset(findings)

    def _decoy_capabilities(self) -> frozenset[str]:
        findings = set()
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                if os.readlink(entry / "ns/pid") != self.decoy_pidns:
                    continue
                status = (entry / "status").read_text()
            except OSError:
                continue  # exited mid-scan
            for line in status.splitlines():
                if line.startswith("CapEff:"):
                    value = line.split()[1]
                    if int(value, 16) != 0:
                        findings.add(f"pid:{entry.name}:CapEff:{value}")
        return frozenset(findings)

    # -- injection (the harness's own fixture; never AZ-06 code) --------------
    def inject(self, kind: str) -> Any:
        ns = self.ns
        if kind == "route_to_protected":
            _run("ip", "-n", ns["decoy"], "route", "add", str(self.PROTECTED_NET), "via",
                 self.ROUTER_DECOY_ADDR)
            return None
        if kind == "published_port":
            listener = _LISTENER.format(host="0.0.0.0", port=self.PUBLISH_PORT)
            return self._spawn("ip", "netns", "exec", ns["front"], sys.executable, "-c", listener)
        if kind == "capability_regranted":
            return self._spawn(
                "nsenter", "-t", str(self.decoy_pid), "-p", "-n", "--", "sleep", "600"
            )
        raise ValueError(f"undeclared drift kind {kind!r}")

    def revert(self, kind: str, handle: Any) -> None:
        if kind == "route_to_protected":
            _run("ip", "-n", self.ns["decoy"], "route", "del", str(self.PROTECTED_NET), "via",
                 self.ROUTER_DECOY_ADDR)
            return
        if kind == "capability_regranted":
            # nsenter forks the joined process; kill everything in the decoy PID
            # namespace except the decoy workload itself.
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit() or int(entry.name) == self.decoy_pid:
                    continue
                try:
                    if os.readlink(entry / "ns/pid") == self.decoy_pidns:
                        os.kill(int(entry.name), 9)
                except OSError:
                    continue
        if handle is not None:
            if handle.poll() is None:
                handle.kill()
            handle.wait(timeout=5)
            if handle in self._procs:
                self._procs.remove(handle)

    # -- active reachability probe (observation; withdraws nothing) ------------
    def _probe_from(self, namespace: str) -> bool:
        code = _PROBE.format(host=self.PROTECTED_ADDR, port=self.PROTECTED_PORT, timeout=0.5)
        result = _run("ip", "netns", "exec", namespace, sys.executable, "-c", code, check=False)
        return result.returncode == 0

    def probe(self) -> bool:
        """Can the decoy side reach the protected side right now?"""

        return self._probe_from(self.ns["decoy"])

    def control_probe(self) -> bool:
        """Can the router reach the protected listener? (Lab sanity, not SO-08.)"""

        return self._probe_from(self.ns["router"])


# -----------------------------------------------------------------------------
# Measurement (backend-agnostic)
# -----------------------------------------------------------------------------


class _Detector(threading.Thread):
    """Polls the lab's sampler and feeds AZ-06's observer. Stops on any error."""

    def __init__(self, lab: Lab, observer: IsolationDriftObserver) -> None:
        super().__init__(daemon=True, name="so08-detector")
        self.lab = lab
        self.observer = observer
        self.error: BaseException | None = None
        # Completed sample->observe cycles. The harness waits on this after a
        # revert: the observer appends a record *before* it updates its active
        # set, so seeing the record (or an empty active set) alone does not
        # mean the cycle that sampled the drift is over.
        self.cycles = 0
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.observer.observe(self.lab.sample())
            except BaseException as exc:  # recorded and surfaced: fail closed
                self.error = exc
                return
            self.cycles += 1
            self._stop_event.wait(POLL_INTERVAL_S)

    def stop(self) -> None:
        self._stop_event.set()
        self.join(timeout=5)


def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *args],
            capture_output=True, text=True, timeout=10, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()


def _owner() -> dict[str, Any]:
    status = _git("status", "--porcelain")
    return {
        "repository": rec.OWNING_REPOSITORY,
        "commit": _git("rev-parse", "HEAD") or "unavailable",
        "worktree_clean": None if status is None else status == "",
    }


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _last_seq(state: RuntimeStateStore) -> int:
    records = recorded_drift(state, ENVIRONMENT_ID)
    return int(records[-1]["_evidence_seq"]) if records else -1


def _wait_detected(
    state: RuntimeStateStore, kind: str, after_seq: int, detector: _Detector
) -> dict[str, Any] | None:
    deadline = time.monotonic() + SAMPLE_TIMEOUT_S
    while time.monotonic() < deadline:
        for record in recorded_drift(state, ENVIRONMENT_ID):
            if (
                int(record["_evidence_seq"]) > after_seq
                and record["metadata"].get("drift_kind") == kind
            ):
                return record
        if detector.error is not None:
            return None
        time.sleep(READBACK_INTERVAL_S)
    return None


def _wait_cleared(
    lab: Lab, observer: IsolationDriftObserver, kind: str, detector: _Detector
) -> bool:
    """Wait until the detector has seen the reverted state.

    Two full cycles must complete after the revert: the first may have
    sampled before it. Without this, the next injection can land while the
    detector is still finishing the cycle that saw the previous one, and the
    observer would treat the new drift as already recorded.
    """

    floor = detector.cycles + 2
    deadline = time.monotonic() + SETTLE_TIMEOUT_S
    while time.monotonic() < deadline:
        if detector.error is not None:
            return False
        if (
            detector.cycles >= floor
            and not lab.sample()[kind]
            and not observer.active_findings()[kind]
        ):
            return True
        time.sleep(POLL_INTERVAL_S / 2)
    return False


def _base_record(lab_description: dict[str, Any], backend: str, run: dict[str, Any]) -> dict:
    return {
        "schema": rec.SCHEMA,
        "objective_id": rec.OBJECTIVE_ID,
        "title": "Deception isolation drift: detect within 2 s, withdraw attacker-route "
        "exposure within 5 s, independent of runtime cleanup",
        "issue_ref": "01rabbit/Azazel-Deception#41",
        "assignment_ref": "01rabbit/Azazel:docs/roadmaps/service-objective-assignments.md SO-08",
        "class": rec.CLASS_VIRTUAL_LAB,
        "gate": False,
        "gate_note": "Virtual-lab regression signal only. SO-08 is hardware-only; no green CI "
        "run and no virtual-lab record satisfies the HIL gate "
        "(docs/live-gate-checklist.md, LIVE_GATES id "
        "hil_host_restart_and_route_drift_injection).",
        "owner": _owner(),
        "product_configuration": {
            "commissioned_identity": rec.VIRTUAL_LAB_NO_IDENTITY,
            "lab_backend": backend,
            "drift_kinds": list(DRIFT_KINDS),
            "detector": {
                "observer": "azazel_deception.runtime.isolation_drift.IsolationDriftObserver",
                "evidence_chain": "azazel_deception.runtime.state.RuntimeStateStore."
                "append_evidence",
                "evidence_record": "Fabric EnvironmentEvent, event_type=failure, "
                "metadata.stage=isolation_drift",
                "poll_interval_ms": POLL_INTERVAL_S * 1000,
                "composed_by": "harness (AZ-06 has no long-running drift monitor yet)",
            },
            "topology": lab_description,
        },
        "clock": {
            "name": "CLOCK_MONOTONIC",
            "source": "time.monotonic_ns() in the harness process",
            "note": "the harness both injects and reads the evidence chain back, so start and "
            "end are on one clock on one host",
        },
        "run": run,
    }


def run_lab(
    lab: Lab,
    *,
    state_root: Path,
    samples_per_kind: int = rec.SAMPLES_PER_KIND,
) -> tuple[dict[str, Any], int]:
    """Run the lab and return ``(record, exit_status)``. Never raises for a lab failure."""

    run = {
        "run_id": str(uuid.uuid4()),
        "harness_version": HARNESS_VERSION,
        "started_at_utc": _utc(),
        "host": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "samples_per_kind": samples_per_kind,
    }
    detection_samples: list[dict[str, Any]] = []
    withdrawal_samples: list[dict[str, Any]] = []
    prerequisites: list[dict[str, Any]] = []
    not_executed_reason: str | None = None
    description: dict[str, Any] = {}

    try:
        description = lab.describe()
        lab.setup()
        state = RuntimeStateStore(state_root)
        observer = IsolationDriftObserver(
            state, environment_id=ENVIRONMENT_ID, package_id=PACKAGE_ID, node_id=NODE_ID
        )

        baseline = lab.sample()
        dirty = {k: sorted(v) for k, v in baseline.items() if v}
        prerequisites.append({
            "id": "baseline_isolated",
            "met": not dirty,
            "detail": "no finding of any declared kind before injection"
            if not dirty else f"baseline already drifted: {dirty}",
        })
        baseline_reach = lab.probe()
        prerequisites.append({
            "id": "baseline_unreachable",
            "met": not baseline_reach,
            "detail": "decoy -> protected probe refused before injection"
            if not baseline_reach else "decoy already reaches the protected side",
        })
        if dirty or baseline_reach:
            raise LabUnavailable("lab is not isolated at baseline; nothing would be measured")

        detector = _Detector(lab, observer)
        detector.start()
        try:
            for kind in DRIFT_KINDS:
                for index in range(samples_per_kind):
                    sample_id = f"so08-{kind}-{index:02d}"
                    after_seq = _last_seq(state)
                    start = time.monotonic_ns()
                    handle = lab.inject(kind)
                    injected = time.monotonic_ns()
                    record = _wait_detected(state, kind, after_seq, detector)
                    end = time.monotonic_ns() if record is not None else None
                    reachable = lab.probe()
                    lab.revert(kind, handle)
                    if detector.error is not None:
                        raise LabUnavailable(f"detector stopped: {detector.error!r}")
                    detection_samples.append({
                        "sample_id": sample_id,
                        "drift_kind": kind,
                        "start_event": "harness about to inject the drift",
                        "start_monotonic_ns": start,
                        "injection_returned_monotonic_ns": injected,
                        "end_event": "harness read the isolation-drift record back from "
                        "AZ-06's evidence chain",
                        "end_monotonic_ns": end,
                        "elapsed_ms": None if end is None else round((end - start) / 1e6, 3),
                        "finding": None if record is None else record["metadata"]["finding"],
                        "evidence_event_id": None if record is None else record["event_id"],
                        "evidence_seq": None if record is None else record["_evidence_seq"],
                    })
                    withdrawal_samples.append({
                        "sample_id": sample_id,
                        "drift_kind": kind,
                        "start_monotonic_ns": start,
                        "end_monotonic_ns": None,
                        "end_event": "not reached: no authority path withdraws the drift "
                        "(Azazel-Edge#412)",
                        "probe_reachable_after_detection": reachable,
                    })
                    if not _wait_cleared(lab, observer, kind, detector):
                        raise LabUnavailable(f"{kind} drift did not clear after revert")
        finally:
            detector.stop()

        chain_ok = state.verify_evidence_chain(ENVIRONMENT_ID)
        prerequisites.append({
            "id": "evidence_chain_intact",
            "met": chain_ok,
            "detail": f"{len(recorded_drift(state, ENVIRONMENT_ID))} isolation-drift records; "
            f"verify_evidence_chain={chain_ok}",
        })
        route = [s for s in withdrawal_samples if s["drift_kind"] == "route_to_protected"]
        exposed = sum(1 for s in route if s["probe_reachable_after_detection"])
        prerequisites.append({
            "id": "route_drift_exposed_protected_side",
            "met": exposed == len(route),
            "detail": f"decoy -> protected probe reached after route injection in "
            f"{exposed}/{len(route)} samples (confirms the injection was a real exposure)",
        })
        if not chain_ok:
            raise LabUnavailable("evidence chain failed verification")
        if exposed != len(route):
            raise LabUnavailable("route injection did not produce reachability in every sample")
    except LabUnavailable as exc:
        not_executed_reason = str(exc)
    except Exception as exc:  # any other failure is still "did not execute", never green
        not_executed_reason = f"harness error: {exc!r}"
    finally:
        try:
            lab.teardown()
        except Exception as exc:  # teardown failure must not mask the run's result
            run["teardown_error"] = repr(exc)

    executed = not_executed_reason is None
    run["finished_at_utc"] = _utc()

    detection_eval = rec.evaluate_samples(detection_samples, bound_ms=rec.DETECTION_BOUND_MS)
    withdrawal_eval = rec.evaluate_samples(withdrawal_samples, bound_ms=rec.WITHDRAWAL_BOUND_MS)
    detection_verdict = (
        ("pass" if detection_eval["holds"] else "fail") if executed else "not_measurable"
    )
    withdrawal_verdict = "not_measurable"

    record = _base_record(description, lab.backend, run)
    record["executed"] = executed
    record["not_executed_reason"] = not_executed_reason
    record["prerequisites"] = prerequisites
    record["parts"] = [
        {
            "name": "detection",
            "owner": "Azazel-Deception (AZ-06): observation",
            "pass_rule": {
                "kind": "every_sample_max_elapsed",
                "bound_ms": rec.DETECTION_BOUND_MS,
                "description": "every sample: drift injected -> recorded in AZ-06's evidence "
                "chain within 2 seconds; an unfinished sample is a violation",
                "evaluated": detection_eval,
            },
            "verdict": detection_verdict,
            "gaps": [
                {
                    "id": "SO08-DETECTOR-COMPOSED-BY-HARNESS",
                    "blocks_verdict": False,
                    "refs": ["src/azazel_deception/runtime/isolation_drift.py"],
                    "summary": "AZ-06 has no long-running drift monitor; the harness polls a "
                    "procfs sampler and feeds the real IsolationDriftObserver. The latency "
                    "measured includes the harness's poll interval.",
                }
            ],
            "samples": detection_samples,
        },
        {
            "name": "withdrawal",
            "owner": "Azazel-Edge authority path (enforcement), measured end-to-end",
            "pass_rule": {
                "kind": "every_sample_max_elapsed",
                "bound_ms": rec.WITHDRAWAL_BOUND_MS,
                "description": "every sample: drift injected -> active TCP probe from the "
                "decoy side no longer reaches the protected side within 5 seconds; "
                "reachability, not teardown",
                "evaluated": withdrawal_eval,
            },
            "probe": {
                "definition": "TCP connect from the decoy network namespace to the protected "
                "listener, 0.5 s timeout; reachable iff the connect succeeds",
                "performed": "once per sample, right after detection, descriptive only",
                "withdraws_anything": False,
            },
            "verdict": withdrawal_verdict,
            "gaps": [rec.edge_withdrawal_gap()],
            "samples": withdrawal_samples,
        },
    ]
    record["verdict"] = rec.overall_verdict([detection_verdict, withdrawal_verdict])
    record["notes"] = [
        "class virtual-lab-regression, gate false: this record is never HIL evidence.",
        "After each sample the harness reverts its own injection; that revert is a test "
        "fixture, is not timed and is not withdrawal.",
    ]

    if not executed:
        status = EXIT_NOT_EXECUTED
    elif detection_verdict == "pass":
        status = EXIT_DETECTION_WITHIN_BOUND
    else:
        status = EXIT_DETECTION_REGRESSION
    return record, status


def main(argv: list[str] | None = None, *, lab: Lab | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--state-root", type=Path, default=None,
                        help="evidence-chain directory (default: a fresh temp dir)")
    args = parser.parse_args(argv)

    lab = lab or NamespaceLab()
    with tempfile.TemporaryDirectory(prefix="so08-state-") as tmp:
        state_root = args.state_root or Path(tmp)
        record, status = run_lab(lab, state_root=state_root)

    problems = rec.validate_record(record)
    if problems and status != EXIT_NOT_EXECUTED:
        # A record the validator refuses is not evidence of anything.
        record["validation_problems"] = problems
        status = EXIT_NOT_EXECUTED
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    detection = record["parts"][0]["pass_rule"]["evaluated"]
    per_kind = {}
    for kind in DRIFT_KINDS:
        values = [
            s["elapsed_ms"] for s in record["parts"][0]["samples"]
            if s["drift_kind"] == kind and s["elapsed_ms"] is not None
        ]
        per_kind[kind] = max(values) if values else None
    print(json.dumps({
        "objective_id": record["objective_id"],
        "class": record["class"],
        "gate": record["gate"],
        "executed": record["executed"],
        "not_executed_reason": record["not_executed_reason"],
        "detection_verdict": record["parts"][0]["verdict"],
        "detection_max_ms_per_kind": per_kind,
        "detection_violations": detection["violations"],
        "withdrawal_verdict": record["parts"][1]["verdict"],
        "verdict": record["verdict"],
        "record": str(args.output),
        "exit_status": status,
    }, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
