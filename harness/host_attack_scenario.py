"""
host_attack_scenario.py -- Replayable Host Attack Scenario & SyscallRecord Generator
====================================================================================
Role D: Adversarial Eval & Delivery (Person D - Avinash)
Zero-Day Detection FYP - Week 4

PURPOSE:
--------
Implements a 5-stage stealth host-attack kill-chain scenario designed to demonstrate
why Pillar 3 (Host eBPF Syscall Monitoring) is indispensable.

KILL-CHAIN STORY:
-----------------
1. Stage 1 (Initial Access & Execution):
   Phishing attachment received -> user executes dropper via execve/clone.
   [T1566.001 Spearphishing Attachment / T1204.002 User Execution]
   - P1 Blindness: Standard email TLS flow, tiny payload (<15 KB).
   - P2 Blindness: Legitimate user (uid: 1000) logged into workstation during normal hours.
   - P3 Anomaly: execve of unsigned binary from /tmp spawned by user session.

2. Stage 2 (Process Injection):
   Dropper injects stealth shellcode into trusted system daemon (sssd/systemd) via ptrace.
   [T1055.008 Process Injection: Ptrace System Calls]
   - P1 Blindness: 100% intra-host memory manipulation, zero network flows emitted.
   - P2 Blindness: Zero identity changes, no IdP token modifications.
   - P3 Anomaly: ptrace(PTRACE_ATTACH / PTRACE_POKETEXT) from user PID to system daemon.

3. Stage 3 (OS Credential Dumping):
   Injected thread elevates privileges and reads sensitive credential stores (/etc/shadow, memory).
   [T1003.001 / T1003.008 OS Credential Dumping]
   - P1 Blindness: Purely local disk/memory operations, zero network packets.
   - P2 Blindness: Local password hashes extracted; not yet replayed against IdP.
   - P3 Anomaly: setuid(0) elevation and openat on /etc/shadow by non-auth daemon context.

4. Stage 4 (Local Persistence):
   Attacker stages persistent backdoor via scheduled configuration / kernel module mount.
   [T1547.001 Boot Autostart / T1547.006 Kernel Modules]
   - P1 Blindness: Local disk/kernel staging, zero network packets.
   - P2 Blindness: Unchanged directory authentication metadata.
   - P3 Anomaly: openat with write mode to /etc/cron.d/ combined with init_module/mount.

5. Stage 5 (Command & Control / Slow Exfiltration):
   Hijacked daemon initiates outbound HTTPS connection to external C2, dripping exfil data.
   [T1071.001 Application Layer Protocol: Web Protocols]
   - P1 Blindness: Standard port 443 TLS 1.3 handshake, benign packet sizing, low rate.
   - P2 Blindness: Assigned workstation communicating over web protocols in office hours.
   - P3 Anomaly: Outbound connect() socket call from sssd daemon (which never speaks to public IPs).

SCHEMA CONFORMANCE & VERIFICATION STATUS:
------------------------------------------
Generates SyscallRecord JSON objects intended to match Person A's eBPF collector
(capture/ebpf_syscall_watcher.py).

NOTE (PENDING VERIFICATION):
As documented in docs/SYSCALLRECORD_RECONCILIATION.md, the argument shapes for
ptrace, clone, init_module, and mount, along with socket address decoding for
connect(), are PROVISIONAL and pending verification against Person A's corrected
eBPF collector. Generated outputs from this script are provisional evaluation
traces, not final checked-in repository artifacts.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "harness" / "results"

# 8 Hooked tracepoints from Pillar 3 roadmap & capture/ebpf_syscall_watcher.py
HOOKED_SYSCALLS = {
    "openat",
    "execve",
    "connect",
    "setuid",
    "clone",
    "ptrace",
    "init_module",
    "mount",
}

# ATT&CK Technique mappings designed for Role C (Aditya) validation
TECHNIQUE_MAP = {
    "stage_1_dropper": {
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "secondary_id": "T1566.001",
        "secondary_name": "Phishing: Spearphishing Attachment",
        "primary_syscall": "execve",
    },
    "stage_2_injection": {
        "technique_id": "T1055.008",
        "technique_name": "Process Injection: Ptrace System Calls",
        "secondary_id": "T1055",
        "secondary_name": "Process Injection",
        "primary_syscall": "ptrace",
    },
    "stage_3_credentials": {
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/shadow",
        "secondary_id": "T1003.001",
        "secondary_name": "OS Credential Dumping: LSASS / Memory",
        "primary_syscall": "openat",
    },
    "stage_4_persistence": {
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "secondary_id": "T1547.006",
        "secondary_name": "Boot or Logon Initialization Scripts: Kernel Modules and Extensions",
        "primary_syscall": "init_module",
    },
    "stage_5_c2_exfil": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols (HTTPS C2)",
        "secondary_id": "T1041",
        "secondary_name": "Exfiltration Over C2 Channel",
        "primary_syscall": "connect",
    },
}


@dataclass
class SyscallRecord:
    """Standard SyscallRecord representation conforming to capture/ebpf_syscall_watcher.py."""
    timestamp: float
    pid: int
    uid: int
    comm: str
    syscall: str
    args: Dict[str, Any]
    ret: int = 0
    ppid: Optional[int] = None
    stage_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    is_attack: bool = False
    blindness_rationale: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "timestamp": round(self.timestamp, 6),
            "pid": self.pid,
            "uid": self.uid,
            "comm": self.comm,
            "syscall": self.syscall,
            "args": self.args,
            "ret": self.ret,
        }
        if self.ppid is not None:
            d["ppid"] = self.ppid
        if self.is_attack:
            d["stage_id"] = self.stage_id
            d["mitre_technique"] = self.mitre_technique
            d["is_attack"] = True
            d["blindness_rationale"] = self.blindness_rationale
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class HostAttackScenario:
    """
    Generates the complete 5-stage host attack kill-chain with interleaved
    benign background activity.
    """

    def __init__(
        self,
        base_time: float = 1756914600.0,
        victim_user: str = "victim_analyst",
        victim_uid: int = 1000,
        victim_pid: int = 4120,
        target_daemon: str = "sssd",
        target_daemon_pid: int = 1084,
        c2_ip: str = "198.51.100.42",
        c2_port: int = 443,
        seed: int = 42,
    ):
        self.base_time = base_time
        self.victim_user = victim_user
        self.victim_uid = victim_uid
        self.victim_pid = victim_pid
        self.target_daemon = target_daemon
        self.target_daemon_pid = target_daemon_pid
        self.c2_ip = c2_ip
        self.c2_port = c2_port
        self.rng = random.Random(seed)

    def generate_stage_1_dropper(self, t0: float) -> List[SyscallRecord]:
        """Stage 1: Spearphishing email attachment executed by victim user."""
        records = []
        t = t0

        # User opens attachment in mail client
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=3800,
                ppid=1,
                uid=self.victim_uid,
                comm="thunderbird",
                syscall="openat",
                args={
                    "dfd": -100,
                    "filename": f"/home/{self.victim_user}/Downloads/invoice_oct.pdf.sh",
                    "flags": 0,  # O_RDONLY
                    "mode": 0,
                },
                ret=4,
                stage_id="stage_1_dropper",
                mitre_technique="T1566.001",
                is_attack=True,
                blindness_rationale="P1: Normal IMAP/HTTPS retrieval. P2: Standard desktop session.",
            )
        )
        t += 0.05

        # Mail client / shell forks child process
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=3800,
                ppid=1,
                uid=self.victim_uid,
                comm="thunderbird",
                syscall="clone",
                args={"flags": 0x00000111, "child_stack": "0x7ffd58", "ptid": 0},
                ret=self.victim_pid,
                stage_id="stage_1_dropper",
                mitre_technique="T1204.002",
                is_attack=True,
                blindness_rationale="P1: No network activity. P2: Standard user process creation.",
            )
        )
        t += 0.02

        # Child execs the dropper payload
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.victim_pid,
                ppid=3800,
                uid=self.victim_uid,
                comm="invoice_oct.sh",
                syscall="execve",
                args={
                    "filename": f"/home/{self.victim_user}/Downloads/invoice_oct.pdf.sh",
                    "argv": ["/bin/sh", f"/home/{self.victim_user}/Downloads/invoice_oct.pdf.sh"],
                },
                ret=0,
                stage_id="stage_1_dropper",
                mitre_technique="T1204.002",
                is_attack=True,
                blindness_rationale="P1: No network flow. P2: Local user execution.",
            )
        )
        t += 0.03

        # Dropper drops staged binary into /tmp
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.victim_pid,
                ppid=3800,
                uid=self.victim_uid,
                comm="invoice_oct.sh",
                syscall="openat",
                args={
                    "dfd": -100,
                    "filename": "/tmp/.payload_dropper",
                    "flags": 0x42,  # O_CREAT|O_TRUNC|O_WRONLY
                    "mode": 0o755,
                },
                ret=5,
                stage_id="stage_1_dropper",
                mitre_technique="T1204.002",
                is_attack=True,
                blindness_rationale="P1: Zero network flows. P2: Local temp file staging.",
            )
        )
        return records

    def generate_stage_2_injection(self, t0: float) -> List[SyscallRecord]:
        """Stage 2: Dropper injects shellcode into daemon via ptrace."""
        records = []
        t = t0

        # ptrace ATTACH to sssd daemon
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.victim_pid,
                ppid=3800,
                uid=self.victim_uid,
                comm="invoice_oct.sh",
                syscall="ptrace",
                args={
                    "request": "PTRACE_ATTACH",
                    "pid": self.target_daemon_pid,
                    "addr": "0x0",
                    "data": "0x0",
                },
                ret=0,
                stage_id="stage_2_injection",
                mitre_technique="T1055.008",
                is_attack=True,
                blindness_rationale="P1: 0 network bytes. P2: No IdP identity or token change.",
            )
        )
        t += 0.04

        # ptrace POKETEXT writing shellcode into daemon process memory
        for i in range(3):
            records.append(
                SyscallRecord(
                    timestamp=t,
                    pid=self.victim_pid,
                    ppid=3800,
                    uid=self.victim_uid,
                    comm="invoice_oct.sh",
                    syscall="ptrace",
                    args={
                        "request": "PTRACE_POKETEXT",
                        "pid": self.target_daemon_pid,
                        "addr": hex(0x7F8000 + i * 8),
                        "data": hex(0x9090909090909090 ^ (i * 0x1111)),
                    },
                    ret=0,
                    stage_id="stage_2_injection",
                    mitre_technique="T1055.008",
                    is_attack=True,
                    blindness_rationale="P1: Intra-process memory overwrite. P2: Clean session.",
                )
            )
            t += 0.01

        # ptrace DETACH / CONT allowing injected daemon thread to run
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.victim_pid,
                ppid=3800,
                uid=self.victim_uid,
                comm="invoice_oct.sh",
                syscall="ptrace",
                args={
                    "request": "PTRACE_DETACH",
                    "pid": self.target_daemon_pid,
                    "addr": "0x0",
                    "data": "0x0",
                },
                ret=0,
                stage_id="stage_2_injection",
                mitre_technique="T1055.008",
                is_attack=True,
                blindness_rationale="P1: Zero packets. P2: Process continues running under daemon PID.",
            )
        )
        return records

    def generate_stage_3_credentials(self, t0: float) -> List[SyscallRecord]:
        """Stage 3: Injected daemon elevates privileges & reads credential stores."""
        records = []
        t = t0

        # setuid to root within daemon context
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="setuid",
                args={"uid": 0},
                ret=0,
                stage_id="stage_3_credentials",
                mitre_technique="T1003.008",
                is_attack=True,
                blindness_rationale="P1: Zero network traffic. P2: Local privilege transition.",
            )
        )
        t += 0.02

        # Open /etc/shadow to harvest password hashes
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="openat",
                args={
                    "dfd": -100,
                    "filename": "/etc/shadow",
                    "flags": 0,  # O_RDONLY
                    "mode": 0,
                },
                ret=6,
                stage_id="stage_3_credentials",
                mitre_technique="T1003.008",
                is_attack=True,
                blindness_rationale="P1: Local disk read. P2: Hashes stored locally, no Kerberos ticket request.",
            )
        )
        t += 0.03

        # Open /proc/$pid/mem or environment strings for token extraction
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="openat",
                args={
                    "dfd": -100,
                    "filename": "/proc/1/environ",
                    "flags": 0,
                    "mode": 0,
                },
                ret=7,
                stage_id="stage_3_credentials",
                mitre_technique="T1003.001",
                is_attack=True,
                blindness_rationale="P1: Pure memory access. P2: Invisible to IdP log monitors.",
            )
        )
        return records

    def generate_stage_4_persistence(self, t0: float) -> List[SyscallRecord]:
        """Stage 4: Backdoor persistence via cron and module/mount staging."""
        records = []
        t = t0

        # Install cron autostart script
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="openat",
                args={
                    "dfd": -100,
                    "filename": "/etc/cron.d/sync_service",
                    "flags": 0x42,  # O_CREAT|O_TRUNC|O_WRONLY
                    "mode": 0o644,
                },
                ret=8,
                stage_id="stage_4_persistence",
                mitre_technique="T1547.001",
                is_attack=True,
                blindness_rationale="P1: 0 network bytes. P2: Local OS cron config modification.",
            )
        )
        t += 0.04

        # Mount staging ramdisk / hide directory
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="mount",
                args={
                    "source": "tmpfs",
                    "target": "/var/run/.cache_sys",
                    "filesystemtype": "tmpfs",
                    "mountflags": 0,
                },
                ret=0,
                stage_id="stage_4_persistence",
                mitre_technique="T1547.006",
                is_attack=True,
                blindness_rationale="P1: Local kernel VFS operation. P2: No directory service change.",
            )
        )
        return records

    def generate_stage_5_c2_exfil(self, t0: float) -> List[SyscallRecord]:
        """Stage 5: Hijacked daemon calls home via HTTPS C2 exfiltration."""
        records = []
        t = t0

        # Hijacked daemon initiates outbound socket connection to C2
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="connect",
                args={
                    "fd": 9,
                    "family": "AF_INET",
                    "ip": self.c2_ip,
                    "port": self.c2_port,
                    "addrlen": 16,
                },
                ret=0,
                stage_id="stage_5_c2_exfil",
                mitre_technique="T1071.001",
                is_attack=True,
                blindness_rationale="P1: Clean 443 TLS 1.3 handshake, tiny 18 KB flow. P2: Office hours workstation.",
            )
        )
        t += 0.05

        # Read encrypted credentials to send
        records.append(
            SyscallRecord(
                timestamp=t,
                pid=self.target_daemon_pid,
                ppid=1,
                uid=0,
                comm=self.target_daemon,
                syscall="openat",
                args={
                    "dfd": -100,
                    "filename": "/tmp/.exfil.enc",
                    "flags": 0,
                    "mode": 0,
                },
                ret=10,
                stage_id="stage_5_c2_exfil",
                mitre_technique="T1041",
                is_attack=True,
                blindness_rationale="P1: Small HTTPS egress flow looks identical to CDN telemetry. P2: Valid machine.",
            )
        )
        return records

    def generate_benign_records(self, t_start: float, t_end: float, count: int = 150) -> List[SyscallRecord]:
        """Generates realistic benign background syscalls on typical Linux system."""
        records = []
        benign_procs = [
            ("systemd", 1, 0, ["openat", "clone"]),
            ("cron", 450, 0, ["openat", "clone", "execve"]),
            ("rsyslogd", 512, 0, ["openat"]),
            ("code", 2980, self.victim_uid, ["openat", "connect"]),
            ("chrome", 3110, self.victim_uid, ["openat", "connect", "clone"]),
            ("bash", 4010, self.victim_uid, ["openat", "execve", "clone"]),
        ]

        timestamps = sorted([self.rng.uniform(t_start, t_end) for _ in range(count)])

        for ts in timestamps:
            comm, pid, uid, allowed_calls = self.rng.choice(benign_procs)
            sc = self.rng.choice(allowed_calls)

            args: Dict[str, Any] = {}
            if sc == "openat":
                safe_files = [
                    "/usr/lib/locale/locale-archive",
                    "/etc/ld.so.cache",
                    "/lib/x86_64-linux-gnu/libc.so.6",
                    f"/home/{self.victim_user}/.bashrc",
                    f"/home/{self.victim_user}/project/main.py",
                    "/var/log/syslog",
                ]
                args = {"dfd": -100, "filename": self.rng.choice(safe_files), "flags": 0, "mode": 0}
            elif sc == "execve":
                safe_cmds = ["/usr/bin/ls", "/usr/bin/grep", "/usr/bin/git", "/usr/bin/date"]
                args = {"filename": self.rng.choice(safe_cmds)}
            elif sc == "connect":
                args = {
                    "fd": self.rng.randint(3, 12),
                    "family": "AF_INET",
                    "ip": self.rng.choice(["10.0.0.1", "10.0.0.53", "172.217.16.206"]),
                    "port": self.rng.choice([53, 80, 443]),
                    "addrlen": 16,
                }
            elif sc == "clone":
                args = {"flags": 0x1200011, "child_stack": "0x7fff00"}

            records.append(
                SyscallRecord(
                    timestamp=ts,
                    pid=pid,
                    uid=uid,
                    comm=comm,
                    syscall=sc,
                    args=args,
                    ret=0,
                    is_attack=False,
                )
            )
        return records

    def build_full_story(self, interleave_benign: bool = True, benign_count: int = 150) -> List[SyscallRecord]:
        """
        Builds the ordered sequence of attack events with optional background benign noise.
        """
        t = self.base_time
        all_records: List[SyscallRecord] = []

        # Step 1: Dropper (t + 5s)
        s1 = self.generate_stage_1_dropper(t + 5.0)
        # Step 2: Injection (t + 12s)
        s2 = self.generate_stage_2_injection(t + 12.0)
        # Step 3: Credentials (t + 18s)
        s3 = self.generate_stage_3_credentials(t + 18.0)
        # Step 4: Persistence (t + 25s)
        s4 = self.generate_stage_4_persistence(t + 25.0)
        # Step 5: C2 (t + 35s)
        s5 = self.generate_stage_5_c2_exfil(t + 35.0)

        attack_records = s1 + s2 + s3 + s4 + s5

        if interleave_benign:
            t_start = self.base_time
            t_end = self.base_time + 45.0
            benign_records = self.generate_benign_records(t_start, t_end, count=benign_count)
            all_records = sorted(attack_records + benign_records, key=lambda r: r.timestamp)
        else:
            all_records = sorted(attack_records, key=lambda r: r.timestamp)

        return all_records


def export_scenario(
    out_dir: Path = DEFAULT_OUT_DIR,
    interleave_benign: bool = True,
    benign_count: int = 150,
) -> tuple[Path, Path]:
    """Exports the scenario to JSON and JSONL formats."""
    out_dir.mkdir(parents=True, exist_ok=True)
    scenario = HostAttackScenario()
    records = scenario.build_full_story(interleave_benign=interleave_benign, benign_count=benign_count)

    jsonl_path = out_dir / "host_attack_story_trace.jsonl"
    json_path = out_dir / "host_attack_story_summary.json"

    # Export JSONL stream
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(r.to_json() + "\n")

    # Export Stage Summary
    attack_only = [r.to_dict() for r in records if r.is_attack]
    summary_data = {
        "title": "Zero-Day FYP - Week 4 Host Attack Scenario Spec",
        "author": "Person D (Avinash) - Adversarial Eval & Delivery",
        "description": "5-stage stealth host attack demonstrating Pillar 3 indispensability against P1/P2 blind spots",
        "trace_file": str(jsonl_path.name),
        "total_records": len(records),
        "attack_events_count": len(attack_only),
        "hooked_tracepoints": sorted(list(HOOKED_SYSCALLS)),
        "technique_mapping": TECHNIQUE_MAP,
        "stages": [
            {
                "stage_id": "stage_1_dropper",
                "name": "Spearphishing Email & Dropper Exec",
                "technique": "T1566.001 / T1204.002",
                "p1_blindness": "Normal IMAP/TLS traffic; payload < 15KB",
                "p2_blindness": "Legitimate user session in normal office hours",
                "p3_catch": "execve of unsigned binary from /tmp spawned by user session",
            },
            {
                "stage_id": "stage_2_injection",
                "name": "Process Injection into Daemon via Ptrace",
                "technique": "T1055.008",
                "p1_blindness": "100% intra-host memory manipulation; 0 network packets",
                "p2_blindness": "No identity/token change at IdP level",
                "p3_catch": "Rare ptrace(PTRACE_ATTACH/POKETEXT) from user PID to sssd daemon",
            },
            {
                "stage_id": "stage_3_credentials",
                "name": "OS Credential Harvesting",
                "technique": "T1003.008 / T1003.001",
                "p1_blindness": "Local disk/memory read; zero network communication",
                "p2_blindness": "Hashes extracted locally; no anomalous IdP login events yet",
                "p3_catch": "setuid(0) elevation and openat on /etc/shadow by sssd context",
            },
            {
                "stage_id": "stage_4_persistence",
                "name": "Local Persistence via Cron & Mount",
                "technique": "T1547.001 / T1547.006",
                "p1_blindness": "Local configuration write; zero network communication",
                "p2_blindness": "Local admin scope; no enterprise directory schema change",
                "p3_catch": "openat write to /etc/cron.d/ with mount/init_module staging",
            },
            {
                "stage_id": "stage_5_c2_exfil",
                "name": "HTTPS C2 Exfiltration",
                "technique": "T1071.001 / T1041",
                "p1_blindness": "Clean 443 TLS 1.3 flow, benign sizing, quiet interval",
                "p2_blindness": "Workstation accessing web endpoints during work hours",
                "p3_catch": "Outbound connect() socket initiated directly from sssd daemon",
            },
        ],
        "attack_events": attack_only,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    return jsonl_path, json_path


def main():
    parser = argparse.ArgumentParser(description="Generate and inspect the Week 4 Host Attack Scenario Spec")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output directory for generated traces")
    parser.add_argument("--no-benign", action="store_true", help="Generate only attack events without benign noise")
    parser.add_argument("--count-benign", type=int, default=150, help="Number of background benign events")
    parser.add_argument("--print-summary", action="store_true", help="Print summary table to stdout")
    args = parser.parse_args()

    jsonl_p, json_p = export_scenario(
        out_dir=args.out_dir,
        interleave_benign=not args.no_benign,
        benign_count=args.count_benign,
    )
    print(f"[+] Successfully generated Host Attack Scenario Trace: {jsonl_p}")
    print(f"[+] Successfully generated Host Attack Summary Spec: {json_p}")

    if args.print_summary or True:
        with open(json_p, "r", encoding="utf-8") as f:
            data = json.load(f)
        print("\n================================================================================")
        print("          ZERO-DAY FYP - WEEK 4 HOST ATTACK SCENARIO SPEC (ROLE D)              ")
        print("================================================================================")
        print(f"Total Syscall Records : {data['total_records']}")
        print(f"Attack Events Count   : {data['attack_events_count']}")
        print(f"Hooked Tracepoints    : {', '.join(data['hooked_tracepoints'])}")
        print("--------------------------------------------------------------------------------")
        print(f"{'Stage ID':<22} | {'ATT&CK':<12} | {'Primary Syscall':<15} | {'P3 Catch Mechanism'}")
        print("--------------------------------------------------------------------------------")
        for s in data["stages"]:
            stage_id = s["stage_id"]
            tech = TECHNIQUE_MAP[stage_id]["technique_id"]
            sc = TECHNIQUE_MAP[stage_id]["primary_syscall"]
            catch = s["p3_catch"][:42] + ("..." if len(s["p3_catch"]) > 42 else "")
            print(f"{stage_id:<22} | {tech:<12} | {sc:<15} | {catch}")
        print("================================================================================\n")


if __name__ == "__main__":
    main()
