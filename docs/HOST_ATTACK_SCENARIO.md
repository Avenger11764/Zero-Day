# Host Attack Scenario Spec: "Operation SilentWhisper" (Pillar 3 Justification)

**Author:** Person D (Avinash — Adversarial Eval & Delivery)  
**Date:** 2026-09-03 (Week 4 Deliverable)  
**Status:** Frozen Spec & Replayable Trace Generator (`harness/host_attack_scenario.py`)  
**Cross-Role Interfaces:** Feeds Person B (`detection/host_ae.py`), validates Person C (`UEBA/ATT&CK_mapper/`), and drives Person D (Dashboard Replay Demo).

---

## 1. Executive Summary: Why Pillar 3 Must Exist

Signature-based defenses and perimeter network monitoring (Pillar 1) are blind to attacks that employ legitimate protocols with low-volume, standard timing and intra-host memory techniques. Identity UEBA (Pillar 2) is blind to intra-host privilege transitions occurring inside an already-authenticated, legitimate user desktop session.

This document specifies a **5-stage stealth kill-chain scenario** (`phishing email → dropper execve → process injection via ptrace → credential dumping → HTTPS C2 exfiltration`). This attack is designed so that:
- **Pillar 1 (Network Flow AE / GNN)** observes standard, benign-looking HTTPS/TLS traffic and stays below the detection threshold ($S_{net} \le 0.28$).
- **Pillar 2 (Identity UEBA)** observes an active, assigned user operating on their registered device during normal office hours ($S_{id} \le 0.15$).
- **Pillar 3 (Host eBPF Syscall Anomaly Detector)** captures anomalous kernel transitions and flags the activity with high confidence ($S_{host} \ge 0.94$).

```
                      +-------------------------------------------------------------+
                      |               Stealth Multi-Stage Host Kill-Chain           |
                      +-------------------------------------------------------------+
                                                     |
        +-------------------------+------------------+------------------+-------------------------+
        |                         |                                     |                         |
        v                         v                                     v                         v
 [1. Dropper Exec]      [2. Process Injection]                [3. Credential Dump]      [4. Persistence & C2]
 execve(/tmp/dropper)    ptrace(PTRACE_ATTACH, sssd)           setuid(0) + /etc/shadow   connect(443) from sssd
        |                         |                                     |                         |
        |                         |                                     |                         |
+---------------+         +---------------+                     +---------------+         +---------------+
| P1: INVISIBLE |         | P1: INVISIBLE |                     | P1: INVISIBLE |         | P1: INVISIBLE |
| (0 Net Flows) |         | (0 Net Flows) |                     | (0 Net Flows) |         | (Normal TLS)  |
+---------------+         +---------------+                     +---------------+         +---------------+
| P2: INVISIBLE |         | P2: INVISIBLE |                     | P2: INVISIBLE |         | P2: INVISIBLE |
| (Valid User)  |         | (Same User)   |                     | (Local Scope) |         | (Work Hours)  |
+---------------+         +---------------+                     +---------------+         +---------------+
| P3: CAUGHT    |         | P3: CAUGHT    |                     | P3: CAUGHT    |         | P3: CAUGHT    |
| Anom. execve  |         | Anom. ptrace  |                     | Anom. setuid  |         | Hijacked Sock |
+---------------+         +---------------+                     +---------------+         +---------------+
```

---

## 2. Stage-by-Stage Attack Specification & Blind-Spot Rationale

### Stage 1: Spearphishing & Dropper Execution
* **Scenario Action:** Victim receives a disguised attachment (`invoice_oct.pdf.sh`) via legitimate email client (`thunderbird`). Opening the attachment triggers a script that writes a hidden ELF binary to `/tmp/.payload_dropper` and invokes it via `execve`.
* **Syscall Sequence (8 Hooked Tracepoints):**
  1. `openat(dfd=-100, filename="/home/victim/Downloads/invoice_oct.pdf.sh", flags=O_RDONLY)`
  2. `clone(flags=SIGCHLD, ...)` $\rightarrow$ spawns child `PID 4120`
  3. `execve(filename="/home/victim/Downloads/invoice_oct.pdf.sh", argv=[...])`
  4. `openat(dfd=-100, filename="/tmp/.payload_dropper", flags=O_CREAT|O_WRONLY|O_TRUNC, mode=0755)`
* **ATT&CK Mapping (for Person C):**
  * Primary: `T1204.002` (User Execution: Malicious File)
  * Secondary: `T1566.001` (Phishing: Spearphishing Attachment)
* **Blind-Spot Rationale:**
  * **Pillar 1 (Network):** Inbound email delivery over standard TLS IMAP/HTTPS port. Payload size is minuscule ($< 15$ KB); zero anomalous connection bursts or unusual ports.
  * **Pillar 2 (UEBA):** Legitimate user (`uid: 1000`) logged into corporate workstation during standard working hours. No anomalous geolocation or authentication failures.
  * **Pillar 3 (Host Catch):** Anomaly detector flags `execve` spawning an executable directly out of `/tmp` with `thunderbird` as the ancestor process.

---

### Stage 2: Process Injection via Ptrace
* **Scenario Action:** The dropper uses kernel debugging primitives (`ptrace`) to attach to a trusted, long-running system daemon (`sssd`, `PID 1084`), writes stealth shellcode into the process memory (`PTRACE_POKETEXT`), and detaches, allowing the hijacked daemon thread to resume execution.
* **Syscall Sequence:**
  1. `ptrace(request=PTRACE_ATTACH, pid=1084, addr=0, data=0)`
  2. `ptrace(request=PTRACE_POKETEXT, pid=1084, addr=0x7F8000, data=0x9090...)` $\times N$
  3. `ptrace(request=PTRACE_DETACH, pid=1084, addr=0, data=0)`
* **ATT&CK Mapping (for Person C):**
  * Primary: `T1055.008` (Process Injection: Ptrace System Calls)
  * Secondary: `T1055` (Process Injection)
* **Blind-Spot Rationale:**
  * **Pillar 1 (Network):** Zero network packets emitted; operations occur entirely in host virtual memory.
  * **Pillar 2 (UEBA):** Identity tokens and directory session states remain untouched.
  * **Pillar 3 (Host Catch):** `ptrace` usage on non-developer production endpoints has a baseline probability approaching 0.0. Inter-PID memory modification is an immediate host-level anomaly.

---

### Stage 3: Privilege Escalation & OS Credential Dumping
* **Scenario Action:** Running within the hijacked daemon context, the injected payload invokes `setuid(0)` to obtain root privileges, then accesses `/etc/shadow` and inspects `/proc/1/environ` to dump password hashes and cached session credentials.
* **Syscall Sequence:**
  1. `setuid(uid=0)` $\rightarrow$ succeeds under daemon root permissions
  2. `openat(dfd=-100, filename="/etc/shadow", flags=O_RDONLY)`
  3. `openat(dfd=-100, filename="/proc/1/environ", flags=O_RDONLY)`
* **ATT&CK Mapping (for Person C):**
  * Primary: `T1003.008` (OS Credential Dumping: /etc/shadow)
  * Secondary: `T1003.001` (OS Credential Dumping: LSASS / Memory)
* **Blind-Spot Rationale:**
  * **Pillar 1 (Network):** Zero network communication.
  * **Pillar 2 (UEBA):** Credential dumping occurs on local storage/RAM before any harvested credentials are used to generate secondary logins.
  * **Pillar 3 (Host Catch):** Non-PAM process opening `/etc/shadow` combined with unexpected `setuid(0)` transition creates a high-reconstruction-error syscall n-gram.

---

### Stage 4: Local Persistence Staging
* **Scenario Action:** Attacker ensures survivability across reboots by writing an autostart job to `/etc/cron.d/sync_service` and staging a hidden memory-backed mount point (`/var/run/.cache_sys`) via `mount`.
* **Syscall Sequence:**
  1. `openat(dfd=-100, filename="/etc/cron.d/sync_service", flags=O_CREAT|O_WRONLY|O_TRUNC, mode=0644)`
  2. `mount(source="tmpfs", target="/var/run/.cache_sys", filesystemtype="tmpfs", mountflags=0)`
* **ATT&CK Mapping (for Person C):**
  * Primary: `T1547.001` (Boot or Logon Autostart Execution: Active Setup / Cron)
  * Secondary: `T1547.006` (Kernel Modules and Extensions / Staging)
* **Blind-Spot Rationale:**
  * **Pillar 1 (Network):** Zero network packets.
  * **Pillar 2 (UEBA):** Local filesystem persistence does not trigger directory or identity schema modifications.
  * **Pillar 3 (Host Catch):** `openat` targeting `/etc/cron.d/` combined with `mount` invoked from an injected daemon context flags as highly anomalous.

---

### Stage 5: HTTPS Command & Control (C2) & Slow Exfiltration
* **Scenario Action:** The hijacked `sssd` daemon initiates an outbound TCP socket connection to external C2 IP `198.51.100.42:443`. It establishes a standard TLS 1.3 session and exfiltrates encrypted credential bundles using a low-and-slow profile (18 KB over 60 seconds).
* **Syscall Sequence:**
  1. `connect(fd=9, family=AF_INET, ip="198.51.100.42", port=443, addrlen=16)`
  2. `openat(dfd=-100, filename="/tmp/.exfil.enc", flags=O_RDONLY)`
* **ATT&CK Mapping (for Person C):**
  * Primary: `T1071.001` (Application Layer Protocol: Web Protocols / HTTPS C2)
  * Secondary: `T1041` (Exfiltration Over C2 Channel)
* **Blind-Spot Rationale:**
  * **Pillar 1 (Network):** Port 443 TLS 1.3 egress, normal packet sizes (800–1200 bytes), normal inter-arrival times, low total volume (18 KB). Indistinguishable from background CDN/telemetry traffic; scores comfortably within the benign network distribution ($S_{net} \approx 0.18$).
  * **Pillar 2 (UEBA):** Assigned endpoint making outbound web requests during business hours.
  * **Pillar 3 (Host Catch):** `sssd` is an internal authentication daemon designed to communicate over local UNIX domain sockets (`/var/run/sssd/`). Emitting an `AF_INET` `connect()` system call to an external public IP address is a catastrophic anomaly at the kernel tracepoint layer.

---

## 3. Replayable Trace Artifacts & Usage

The scenario is implemented in `harness/host_attack_scenario.py` and produces two artifacts in `harness/results/`:

1. **`host_attack_story_trace.jsonl`**: A stream of 166 JSON-serialized `SyscallRecord` events (16 attack events interleaved with 150 realistic benign background syscalls).
2. **`host_attack_story_summary.json`**: Structured metadata detailing stage transitions, ATT&CK codes, hooked tracepoints, and pillar blindness rationales.

### Running the Generator:
```bash
# Generate trace with interleaved background noise (default 150 benign events)
python harness/host_attack_scenario.py

# Generate clean attack-only trace
python harness/host_attack_scenario.py --no-benign

# Custom output location
python harness/host_attack_scenario.py --out-dir harness/results/
```

---

## 4. Proposed `SyscallRecord` Schema Shape (For Person A Week 6 Freeze)

As of Week 4, `schemas/` contains `feature_vector.json` and `scored_alert.json`. The formal `schemas/SyscallRecord.json` schema is planned for Week 6. The generator in `harness/host_attack_scenario.py` establishes the proposed contract:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SyscallRecord",
  "type": "object",
  "properties": {
    "timestamp": {
      "type": "number",
      "description": "Epoch timestamp in seconds with microsecond precision"
    },
    "pid": {
      "type": "integer",
      "description": "Process ID emitting the syscall"
    },
    "ppid": {
      "type": "integer",
      "description": "Parent Process ID"
    },
    "uid": {
      "type": "integer",
      "description": "User ID of the process"
    },
    "comm": {
      "type": "string",
      "description": "Process command name (TASK_COMM_LEN, max 16 chars)"
    },
    "syscall": {
      "type": "string",
      "enum": ["openat", "execve", "connect", "setuid", "clone", "ptrace", "init_module", "mount"],
      "description": "Syscall name matching one of the 8 hooked eBPF tracepoints"
    },
    "args": {
      "type": "object",
      "description": "Syscall-specific arguments extracted from kernel registers"
    },
    "ret": {
      "type": "integer",
      "description": "Syscall return value (0 for success, negative for errno)"
    }
  },
  "required": ["timestamp", "pid", "uid", "comm", "syscall", "args"]
}
```

---

## 5. Cross-Role Integration Checklist

| Role | Teammate | How This Artifact is Used |
|---|---|---|
| **A** | Saharsh (Capture) | Frozen reference for `SyscallRecord` field names and argument shapes before finalizing Week 6 eBPF collector. |
| **B** | Deep (Detection) | Replayable input stream to test and benchmark `detection/host_ae.py` without waiting for live Linux VMs. |
| **C** | Aditya (Explainability) | Exact test scenario to validate the Syscall $\rightarrow$ ATT&CK mapper (`T1204.002`, `T1055.008`, `T1003.008`, `T1547.001`, `T1071.001`). |
| **D** | Avinash (Self) | Core dataset driving the SOC Dashboard interactive attack replay demo. |
