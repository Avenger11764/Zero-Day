# SyscallRecord Reconciliation Report: Harness Spec (Person D) vs. eBPF Collector (Person A)

**Author:** Person D (Avinash — Adversarial Eval & Delivery)  
**Date:** 2026-09-03  
**Target:** Aligning `harness/host_attack_scenario.py` with `capture/ebpf_syscall_watcher.py`  
**Audience:** Team (Person A: Saharsh, Person B: Deep, Person C: Aditya, Person D: Avinash)  
**Artifact Path:** `docs/SYSCALLRECORD_RECONCILIATION.md`

---

## Executive Summary

During Week 4, Person D built a 5-stage stealth host-attack kill-chain scenario (`harness/host_attack_scenario.py`) to serve as a mock `SyscallRecord` stream for Person B's host autoencoder (`detection/host_ae.py`) and Person C's ATT&CK mapper (`UEBA/ATT&CK_mapper/`). In parallel, Person A delivered the initial eBPF/BCC live watcher (`capture/ebpf_syscall_watcher.py`).

A side-by-side reconciliation reveals **3 critical mismatches**:
1. **Syscall Coverage Gap:** Person D's kill-chain scenario relies on `ptrace`, `clone`, `init_module`, and `mount`. Person A's watcher currently hooks `open`, `openat`, `execve`, `execveat`, `connect`, `setuid`, `setgid`, `setresuid`. Specifically, **`ptrace` is not hooked by Person A**, causing Stage 2 (Process Injection, `T1055.008`) to produce **zero real signal** in live capture.
2. **`connect` Arguments Semantic Mismatch:** Person A passes raw user-space memory pointers (`uservaddr: "0x7ffd..."`) as a hex string, whereas Person D's mock trace assumes structured network endpoint data (`ip: "198.51.100.42"`, `port: 443`). Downstream consumers parsing `ip`/`port` will crash on Person A's output.
3. **Telemetry vs. Harness Metadata:** Person D's dataclass includes evaluation metadata (`stage_id`, `mitre_technique`, `is_attack`, `blindness_rationale`, `ret`, `ppid`) that are not emitted by Person A's raw tracepoints.

---

## 1. Field-Level Diff

Comparison between `SyscallRecord` dataclass in `harness/host_attack_scenario.py` and the JSON dictionary emitted by `print_event()` in `capture/ebpf_syscall_watcher.py`:

| Field Name | In Person D (Harness) | In Person A (Watcher) | Status | Downstream Impact / Notes |
|---|---|---|---|---|
| `timestamp` | `float` (seconds, $\mu$s precision) | `float` (`event.ts / 1e9`) | **MATCH** | Identical unit and representation. |
| `pid` | `int` | `int` (`bpf_get_current_pid_tgid() >> 32`) | **MATCH** | Identical. |
| `uid` | `int` | `int` (`bpf_get_current_uid_gid()`) | **MATCH** | Identical. |
| `comm` | `str` (max 16 chars) | `str` (`bpf_get_current_comm()`) | **MATCH** | Identical Linux `TASK_COMM_LEN` string. |
| `syscall` | `str` (syscall name) | `str` (mapped from custom ID) | **MATCH** | Names match standard syscall strings. |
| `args` | `dict[str, Any]` | `dict[str, Any]` | **MATCH (Structure)** | Structure matches; see Section 3 for key-level diffs. |
| `ret` | `int` (default 0) | *Absent* | **MY_EXTRA_FIELD** | **Harmless / Additive.** A hooks `sys_enter_*` (entry probes) which cannot see exit return codes. Ignored by unsupervised AE. |
| `ppid` | `Optional[int]` | *Absent* | **MY_EXTRA_FIELD** | **Harmless / Additive.** A does not traverse `task->real_parent->tgid`. |
| `stage_id` | `Optional[str]` | *Absent* | **MY_EXTRA_FIELD** | **Harness-Only Metadata.** Ground truth label; must be ignored by unsupervised models. |
| `mitre_technique` | `Optional[str]` | *Absent* | **MY_EXTRA_FIELD** | **Harness-Only Metadata.** Used for Person C's ATT&CK validation. |
| `is_attack` | `bool` | *Absent* | **MY_EXTRA_FIELD** | **Harness-Only Metadata.** Evaluation binary label. |
| `blindness_rationale` | `Optional[str]` | *Absent* | **MY_EXTRA_FIELD** | **Harness-Only Metadata.** Academic justification annotation. |

> **Conclusion on Fields:** All 6 core telemetry fields (`timestamp`, `pid`, `uid`, `comm`, `syscall`, `args`) match in name and type. Person D's extra fields are non-breaking harness metadata.

---

## 2. Syscall Coverage Diff

Comparison between Person D's `HOOKED_SYSCALLS` and Person A's `SYSCALL_MAP`:

```
Person D Spec:   { openat, execve, connect, setuid, clone, ptrace, init_module, mount }
Person A Live:   { open, openat, execve, execveat, connect, setuid, setgid, setresuid }
```

### Breakdown of Coverage Mismatches:

| Syscall | In Person D? | In Person A? | Kill-Chain Stage Dependent on Syscall | Impact if Unhooked in Live Collector |
|---|---|---|---|---|
| **`ptrace`** | **YES** | **NO** | **Stage 2: Process Injection (`T1055.008`)** | **FATAL TO STAGE 2.** Process injection produces **zero live events**. The system becomes blind to in-memory shellcode injection into `sssd`. |
| **`clone`** | **YES** | **NO** | Stage 1: Dropper Fork (`T1204.002`) | **MODERATE.** Child execution is still caught by `execve`, but process tree fork telemetry is lost. |
| **`init_module`** | **YES** | **NO** | Stage 4: Kernel Persistence (`T1547.006`) | **HIGH FOR KERNEL HOOKS.** Direct kernel module loading becomes completely invisible. |
| **`mount`** | **YES** | **NO** | Stage 4: Ramdisk / Hide Staging | **MODERATE.** Ramdisk tmpfs staging is lost; stage falls back to plain file write. |
| `open` | NO | **YES** | N/A (Legacy open) | Benign; captures older binaries using 32-bit/legacy `open()`. |
| `execveat` | NO | **YES** | N/A (Modern execve variant) | Benign; improves coverage for descriptor-based execution. |
| `setgid` | NO | **YES** | N/A (Group ID elevation) | Benign; complements `setuid`. |
| `setresuid` | NO | **YES** | N/A (Real/Effective/Saved UID) | Benign; captures fine-grained privilege changes. |

### The Core Problem for Pillar 3:
Stage 2 (Process Injection via `ptrace`) is the **flagship justification for Pillar 3**:
* It emits **0 network packets** (Pillar 1 blind).
* It creates **0 identity login anomalies** (Pillar 2 blind).
* If Person A does not hook `ptrace`, this stage is also **100% blind on Pillar 3 live captures**.

---

## 3. Arguments Shape Diff (Overlapping Syscalls)

For the 4 syscalls present in both sets (`openat`, `execve`, `connect`, `setuid`), the argument dictionaries were compared:

### 1. `openat`
* **Person A:** `{"dfd": int, "filename": str, "flags": int, "mode": int}`
* **Person D:** `{"dfd": int, "filename": str, "flags": int, "mode": int}`
* **Verdict:** **PERFECT MATCH.**

### 2. `execve`
* **Person A:** `{"filename": str}`
* **Person D:** `{"filename": str, "argv": list[str]}`
* **Verdict:** **MINOR DIFFERENCE.** Person D includes `argv` list for richer context. Person A only reads string at register arg. Downstream code checking `args.get("filename")` works identically.

### 3. `connect` — CRITICAL SEMANTIC MISMATCH
* **Person A:** `{"fd": int, "uservaddr": str (hex pointer, e.g. "0x7ffd58"), "addrlen": int}`
* **Person D:** `{"fd": int, "family": "AF_INET", "ip": "198.51.100.42", "port": 443, "addrlen": 16}`
* **Verdict:** **BREAKING MISMATCH.**
  * Person A casts `(u64)args->uservaddr` to a hex string representing the memory address of `struct sockaddr` in user memory. It does not dereference or parse the IP/port.
  * Person D's mock trace assumes parsed socket destination (`ip`, `port`, `family`).
  * If Person B's detector or Person D's dashboard expects `args["ip"]` or `args["port"]`, it will throw a `KeyError` on Person A's live output.

### 4. `setuid`
* **Person A:** `{"uid": int}`
* **Person D:** `{"uid": int}`
* **Verdict:** **PERFECT MATCH.**

---

## 4. Remediation Options & Recommendation

### Option (a): Person A Extends `capture/ebpf_syscall_watcher.py` (RECOMMENDED)
Person A expands the BCC watcher from 8 to 12 tracepoints by adding `ptrace`, `clone`, `init_module`, and `mount`.

**Exact BCC Probe Additions Needed in `capture/ebpf_syscall_watcher.py`:**
```c
// In bpf_text:

// 9. ptrace
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    submit_event((struct pt_regs *)args, 9, args->request, args->pid, args->addr, args->data, NULL);
    return 0;
}

// 10. clone
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    submit_event((struct pt_regs *)args, 10, args->clone_flags, args->newsp, args->parent_tidptr, args->child_tidptr, NULL);
    return 0;
}

// 11. init_module
TRACEPOINT_PROBE(syscalls, sys_enter_init_module) {
    submit_event((struct pt_regs *)args, 11, args->len, 0, 0, 0, args->umod);
    return 0;
}

// 12. mount
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    submit_event((struct pt_regs *)args, 12, args->flags, 0, 0, 0, args->dev_name);
    return 0;
}
```
**In Python `print_event()`:**
```python
SYSCALL_MAP = {
    1: "open", 2: "openat", 3: "execve", 4: "execveat",
    5: "connect", 6: "setuid", 7: "setgid", 8: "setresuid",
    9: "ptrace", 10: "clone", 11: "init_module", 12: "mount"
}
# args_dict handlers:
elif syscall_name == "ptrace":
    args_dict = {"request": event.arg1, "pid": event.arg2, "addr": hex(event.arg3), "data": hex(event.arg4)}
elif syscall_name == "clone":
    args_dict = {"flags": hex(event.arg1), "child_stack": hex(event.arg2)}
elif syscall_name == "init_module":
    args_dict = {"len": event.arg1, "umod": event.str_arg.decode('utf-8', 'replace')}
elif syscall_name == "mount":
    args_dict = {"flags": event.arg1, "dev_name": event.str_arg.decode('utf-8', 'replace')}
```

* **Pros:** Preserves the full academic strength of Pillar 3; captures process injection (`T1055.008`) and kernel persistence (`T1547.006`).
* **Cons:** Takes ~30 minutes of Person A's time to add 4 probes.

---

### Option (b): Person D Redesigns Kill-Chain to Fit Person A's Existing 8 Syscalls
Person D modifies `harness/host_attack_scenario.py` to only use `{open, openat, execve, execveat, connect, setuid, setgid, setresuid}`.

* **Modifications Required:**
  * Drop `ptrace` (Stage 2) $\rightarrow$ Replace with running a secondary payload script via `execve` or hijacking dynamic linker via `openat` (`/etc/ld.so.preload`).
  * Drop `init_module`/`mount` (Stage 4) $\rightarrow$ Rely purely on cron configuration write via `openat` (`/etc/cron.d/`).
* **Pros:** Person A does not have to modify the eBPF watcher.
* **Cons:** **Weakens the thesis.** Process Injection (`T1055.008`) is lost. The attack story degenerates into simple file writes and script executions, which standard endpoint file integrity monitors (FIM) or auditd already catch. The unique value of eBPF kernel-level anomaly detection is severely diluted.

---

### Formal Recommendation:
> **Execute Option (a).**  
> `ptrace` monitoring is the quintessential reason to use eBPF over network-only detection. Expanding from 8 to 12 tracepoints in Week 4 has negligible CPU overhead ($< 1.5\%$) and ensures Person B trains on the exact features that catch zero-day in-memory threats.

---

## 5. Telemetry Shape vs. Evaluation Metadata (Open Questions)

### Clarification on Extra Fields:
Person D's dataclass outputs two tiers of fields:
1. **Raw Telemetry Stream (Production):**
   * `timestamp`, `pid`, `uid`, `comm`, `syscall`, `args` (and optionally `ppid`, `ret`).
   * This is what Person A emits and what Person B's `detection/host_ae.py` consumes to compute reconstruction error.
2. **Harness Evaluation Envelope (Adversarial Eval & Demo):**
   * `is_attack`: Ground-truth label for ROC-AUC calculation in `experiments/`.
   * `stage_id` & `mitre_technique`: Required by Person C's ATT&CK mapper to verify technique attribution.
   * `blindness_rationale`: Used by Person D's SOC Dashboard preview drawer.

### Open Questions for Team Alignment:
1. **`connect` Parsing:** Should Person A parse `sockaddr_in` (to extract human-readable IP and port) inside the eBPF/Python collector, or should Person B's feature extractor (`M4`) accept raw `uservaddr` hex and leave network-layer decoding to Pillar 1?
2. **`ppid` Inclusion:** Should Person A add `ppid` extraction in eBPF via `task->real_parent->tgid` to enable parent-child process anomaly detection?
3. **Formal Schema Location:** Once Person A and D agree on Option (a), Person A will authoritatively freeze `schemas/SyscallRecord.json` in Week 6.
