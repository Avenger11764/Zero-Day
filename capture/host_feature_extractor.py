"""
Host Feature Extraction Engine — Pillar 3, Week 5 (Person A: Saharsh - Data & Capture).

Extracts rich multi-modal host features from streams of SyscallRecord objects or
ADFA-LD / LID-DS trace files:
  1. N-Gram Frequency & Transition Models (1-gram through 6-gram windows)
  2. Process Context & Lineage (UID/GID, root privilege, PPID tree changes, comm entropy)
  3. Return-Value Distribution (error rates, EPERM/ENOENT/EACCES error codes, success ratio)
  4. Inter-Syscall Timing Dynamics (mean, std, min, max, burstiness, rate)
  5. Critical Argument & Attack Surface Indicators (sensitive paths, network sockets, ptrace, rootkits)

Outputs a fixed-length Host FeatureVector block conforming to schemas/host_feature_vector.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# ── DEFAULT PATHS ─────────────────────────────────────────────────────────────
DEFAULT_DATA_ROOT_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "data" / "practice" / "raw_adfa_ld" / "ADFA-LD",
    Path(__file__).resolve().parent.parent / "data" / "practice" / "raw_adfa_ld" / "ADFA-LD" / "ADFA-LD",
    Path(__file__).resolve().parent.parent / "data" / "practice" / "raw_adfa_ld" / "a-labelled-version-of-the-ADFA-LD-dataset-master",
]

# Sensitive paths and indicators
SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root", "/.ssh",
    "/etc/ld.so.preload", "/etc/crontab", "/dev/mem", "/dev/kmem",
    "/proc/kcore", "/tmp", "/dev/shm", "/var/tmp"
]

CRITICAL_SYSCALLS = [
    "execve", "execveat", "openat", "connect", "setuid", "setresuid",
    "setgid", "ptrace", "clone", "init_module", "finit_module", "mount"
]

# Standard Linux errno mappings for return value distribution
ERRNO_MAP = {
    1: "EPERM",
    2: "ENOENT",
    3: "ESRCH",
    9: "EBADF",
    12: "ENOMEM",
    13: "EACCES",
    14: "EFAULT",
    17: "EEXIST",
    22: "EINVAL",
    111: "ECONNREFUSED"
}


@dataclass
class SyscallRecord:
    """Canonical SyscallRecord structure matching schemas/syscall_record.json."""
    timestamp: float
    pid: int
    ppid: int = 1
    uid: int = 1000
    comm: str = ""
    syscall: str = ""
    args: Dict[str, Any] = field(default_factory=dict)
    ret: int = 0
    stage_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    is_attack: bool = False
    blindness_rationale: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> SyscallRecord:
        return cls(
            timestamp=float(d.get("timestamp", 0.0)),
            pid=int(d.get("pid", 1000)),
            ppid=int(d.get("ppid", 1)),
            uid=int(d.get("uid", 1000)),
            comm=str(d.get("comm", "")),
            syscall=str(d.get("syscall", "")),
            args=d.get("args", {}) if isinstance(d.get("args"), dict) else {},
            ret=int(d.get("ret", 0)),
            stage_id=d.get("stage_id"),
            mitre_technique=d.get("mitre_technique"),
            is_attack=bool(d.get("is_attack", False)),
            blindness_rationale=d.get("blindness_rationale")
        )


class HostFeatureExtractor:
    """
    Extracts the full 128-dimensional Host FeatureVector from sequences/streams of SyscallRecords.
    
    Dimension Breakdown (Total: 128 dimensions):
      - 0..49   (50 dims): Pinned 1-gram / top unigram syscall frequency distribution
      - 50..69  (20 dims): Pinned / hashed 2-gram transition pattern distribution
      - 70..89  (20 dims): Higher-order n-gram motif hash projections (3-gram to 6-gram)
      - 90..99  (10 dims): Process context & lineage features
      - 100..109(10 dims): Return value & POSIX errno distributions
      - 110..119(10 dims): Inter-syscall timing dynamics & burstiness
      - 120..127( 8 dims): Critical security indicators & sensitive argument hits
    """

    FEATURE_NAMES = (
        [f"sc_1gram_{i}" for i in range(50)] +
        [f"sc_2gram_{i}" for i in range(20)] +
        [f"sc_ngram_hash_{i}" for i in range(20)] +
        [
            "ctx_is_root", "ctx_uid_changes", "ctx_ppid_is_init", "ctx_comm_entropy",
            "ctx_unique_pids", "ctx_spawn_rate", "ctx_shell_origin", "ctx_priv_transition",
            "ctx_orphan_rate", "ctx_comm_len_norm"
        ] +
        [
            "ret_success_rate", "ret_error_rate", "ret_eperm_ratio", "ret_enoent_ratio",
            "ret_eacces_ratio", "ret_eexist_ratio", "ret_econnrefused_ratio", "ret_other_err_ratio",
            "ret_mean_err_code", "ret_err_entropy"
        ] +
        [
            "time_mean_delta", "time_std_delta", "time_min_delta", "time_max_delta",
            "time_median_delta", "time_burstiness", "time_event_rate", "time_inter_arrival_entropy",
            "time_log_total_dur", "time_log_count"
        ] +
        [
            "sec_sensitive_path_hits", "sec_execve_count_norm", "sec_ptrace_flag", "sec_rootkit_module_flag",
            "sec_mount_flag", "sec_net_connect_rate", "sec_priv_port_connect", "sec_attack_surface_score"
        ]
    )

    VECTOR_DIM = 128

    def __init__(self, vocab: Optional[Dict[str, int]] = None, bigram_vocab: Optional[Dict[str, int]] = None):
        self.vocab = vocab or {}
        self.bigram_vocab = bigram_vocab or {}
        self.unk_idx = 49  # Reserved for out-of-vocabulary 1-grams

    def fit_vocab(self, train_traces: List[List[str]], top_k_unigrams: int = 49, top_k_bigrams: int = 20) -> None:
        """Fit unigram and bigram vocabularies from benign training traces."""
        unigram_counts = Counter()
        bigram_counts = Counter()

        for seq in train_traces:
            for s in seq:
                unigram_counts[s] += 1
            for i in range(len(seq) - 1):
                bg = f"{seq[i]}->{seq[i+1]}"
                bigram_counts[bg] += 1

        # Most common unigrams
        top_u = [item[0] for item in unigram_counts.most_common(top_k_unigrams)]
        self.vocab = {name: idx for idx, name in enumerate(top_u)}

        # Most common bigrams
        top_b = [item[0] for item in bigram_counts.most_common(top_k_bigrams)]
        self.bigram_vocab = {name: idx for idx, name in enumerate(top_b)}

    def extract_from_records(self, records: List[SyscallRecord]) -> np.ndarray:
        """Extract a 128-dimensional Host FeatureVector from a list of SyscallRecords."""
        if not records:
            return np.zeros(self.VECTOR_DIM, dtype=np.float32)

        feat = np.zeros(self.VECTOR_DIM, dtype=np.float32)
        n = len(records)
        syscall_names = [r.syscall for r in records]

        # ── 1. 1-GRAM FREQUENCIES (dims 0..49) ────────────────────────────────
        unigram_vec = np.zeros(50, dtype=np.float32)
        for s in syscall_names:
            idx = self.vocab.get(s, self.unk_idx)
            if idx < 50:
                unigram_vec[idx] += 1.0
        feat[0:50] = unigram_vec / max(n, 1)

        # ── 2. 2-GRAM TRANSITIONS (dims 50..69) ───────────────────────────────
        bigram_vec = np.zeros(20, dtype=np.float32)
        if n >= 2:
            for i in range(n - 1):
                bg = f"{syscall_names[i]}->{syscall_names[i+1]}"
                if bg in self.bigram_vocab:
                    b_idx = self.bigram_vocab[bg]
                    if b_idx < 20:
                        bigram_vec[b_idx] += 1.0
            feat[50:70] = bigram_vec / max(n - 1, 1)

        # ── 3. HIGHER-ORDER N-GRAM HASH MOTIFS (dims 70..89) ─────────────────
        # Uses fast rolling polynomial hashing for 3-grams through 6-grams across 20 hash bins
        sids = [self.vocab.get(s, self.unk_idx) for s in syscall_names]
        ngram_hash_vec = np.zeros(20, dtype=np.float32)
        total_ngrams = 0
        if n >= 3:
            for k in (3, 4, 5, 6):
                if n >= k:
                    h = 0
                    mult = pow(31, k - 1, 1000000007)
                    for j in range(k):
                        h = (h * 31 + sids[j]) % 1000000007
                    ngram_hash_vec[h % 20] += 1.0
                    total_ngrams += 1
                    for i in range(1, n - k + 1):
                        h = ((h - sids[i - 1] * mult) * 31 + sids[i + k - 1]) % 1000000007
                        ngram_hash_vec[h % 20] += 1.0
                        total_ngrams += 1
        if total_ngrams > 0:
            feat[70:90] = ngram_hash_vec / total_ngrams

        # ── 4. PROCESS CONTEXT & LINEAGE (dims 90..99) ────────────────────────
        uids = [r.uid for r in records]
        pids = [r.pid for r in records]
        ppids = [r.ppid for r in records]
        comms = [r.comm for r in records]

        is_root = 1.0 if any(u == 0 for u in uids) else 0.0
        uid_changes = 1.0 if len(set(uids)) > 1 else 0.0
        ppid_is_init = sum(1.0 for p in ppids if p == 1) / n
        
        # Comm string entropy
        all_comm_str = "".join(comms)
        comm_char_counts = Counter(all_comm_str)
        comm_len = len(all_comm_str)
        comm_entropy = 0.0
        if comm_len > 0:
            for c, cnt in comm_char_counts.items():
                p = cnt / comm_len
                comm_entropy -= p * math.log2(p)
        comm_entropy = min(comm_entropy / 8.0, 1.0)  # normalized

        unique_pids_ratio = min(len(set(pids)) / 10.0, 1.0)
        spawn_rate = min(sum(1.0 for s in syscall_names if s in ("clone", "fork", "vfork")) / n, 1.0)
        
        shell_origin = 1.0 if any(any(sh in c.lower() for sh in ("sh", "bash", "zsh", "dash", "nc", "python")) for c in comms) else 0.0
        priv_transition = 1.0 if any(s in ("setuid", "setresuid", "setgid") for s in syscall_names) else 0.0
        orphan_rate = sum(1.0 for p, pp in zip(pids, ppids) if pp <= 1 and p > 100) / n
        comm_len_norm = min(np.mean([len(c) for c in comms]) / 16.0, 1.0) if comms else 0.0

        feat[90:100] = np.array([
            is_root, uid_changes, ppid_is_init, comm_entropy,
            unique_pids_ratio, spawn_rate, shell_origin, priv_transition,
            orphan_rate, comm_len_norm
        ], dtype=np.float32)

        # ── 5. RETURN VALUE & POSIX ERRNO DISTRIBUTION (dims 100..109) ───────
        rets = [r.ret for r in records]
        success_count = sum(1 for r in rets if r == 0)
        error_count = sum(1 for r in rets if r < 0 or r > 0)
        
        ret_success_rate = success_count / n
        ret_error_rate = error_count / n

        # Specific errors (encoded either as negative errno or positive code)
        abs_errs = [abs(r) for r in rets if r != 0]
        err_counts = Counter(abs_errs)
        n_err = max(len(abs_errs), 1)

        eperm_ratio = err_counts[1] / n_err
        enoent_ratio = err_counts[2] / n_err
        eacces_ratio = err_counts[13] / n_err
        eexist_ratio = err_counts[17] / n_err
        econnrefused_ratio = err_counts[111] / n_err
        other_err_ratio = sum(cnt for code, cnt in err_counts.items() if code not in (1, 2, 13, 17, 111)) / n_err

        mean_err_code = min(np.mean(abs_errs) / 133.0, 1.0) if abs_errs else 0.0
        
        err_entropy = 0.0
        if abs_errs:
            for code, cnt in err_counts.items():
                p = cnt / len(abs_errs)
                err_entropy -= p * math.log2(p)
            err_entropy = min(err_entropy / 5.0, 1.0)

        feat[100:110] = np.array([
            ret_success_rate, ret_error_rate, eperm_ratio, enoent_ratio,
            eacces_ratio, eexist_ratio, econnrefused_ratio, other_err_ratio,
            mean_err_code, err_entropy
        ], dtype=np.float32)

        # ── 6. INTER-SYSCALL TIMING DYNAMICS (dims 110..119) ──────────────────
        timestamps = [r.timestamp for r in records]
        if n >= 2:
            deltas = np.diff(timestamps)
            deltas = np.maximum(deltas, 0.0)  # guard against non-monotonic ticks
            mean_dt = float(np.mean(deltas))
            std_dt = float(np.std(deltas))
            min_dt = float(np.min(deltas))
            max_dt = float(np.max(deltas))
            med_dt = float(np.median(deltas))
            
            burstiness = (std_dt - mean_dt) / (std_dt + mean_dt + 1e-7)
            total_dur = max(timestamps[-1] - timestamps[0], 1e-6)
            event_rate = min(n / total_dur / 1000.0, 1.0)
            
            # Delta distribution entropy across 5 logarithmic bins
            hist, _ = np.histogram(np.log1p(deltas), bins=5)
            hist = hist / max(np.sum(hist), 1)
            time_entropy = -float(np.sum([p * np.log2(p) for p in hist if p > 0])) / 2.32
            
            log_dur = min(math.log10(max(total_dur, 1e-4) + 1.0) / 4.0, 1.0)
        else:
            mean_dt = std_dt = min_dt = max_dt = med_dt = burstiness = event_rate = time_entropy = log_dur = 0.0

        log_count = min(math.log10(n + 1.0) / 5.0, 1.0)

        feat[110:120] = np.array([
            min(mean_dt, 10.0) / 10.0,
            min(std_dt, 10.0) / 10.0,
            min(min_dt, 10.0) / 10.0,
            min(max_dt, 100.0) / 100.0,
            min(med_dt, 10.0) / 10.0,
            (burstiness + 1.0) / 2.0,  # scale to [0, 1]
            event_rate,
            min(time_entropy, 1.0),
            log_dur,
            log_count
        ], dtype=np.float32)

        # ── 7. ATTACK SURFACE & SENSITIVE ARGUMENT HITS (dims 120..127) ───────
        sensitive_path_hits = 0.0
        execve_count = 0.0
        ptrace_flag = 0.0
        rootkit_module_flag = 0.0
        mount_flag = 0.0
        net_connect_count = 0.0
        priv_port_connect = 0.0

        for r in records:
            if r.syscall in ("execve", "execveat"):
                execve_count += 1.0
            elif r.syscall == "ptrace":
                ptrace_flag = 1.0
            elif r.syscall in ("init_module", "finit_module"):
                rootkit_module_flag = 1.0
            elif r.syscall == "mount":
                mount_flag = 1.0
            elif r.syscall == "connect":
                net_connect_count += 1.0
                port = r.args.get("port")
                if port and isinstance(port, int) and port < 1024:
                    priv_port_connect = 1.0

            # Inspect argument paths
            filename = r.args.get("filename") or r.args.get("umod") or r.args.get("dev_name") or ""
            if any(sp in str(filename) for sp in SENSITIVE_PATHS):
                sensitive_path_hits += 1.0

        sens_path_norm = min(sensitive_path_hits / max(n, 1) * 10.0, 1.0)
        execve_norm = min(execve_count / max(n, 1) * 5.0, 1.0)
        connect_rate = min(net_connect_count / max(n, 1) * 5.0, 1.0)
        
        attack_surface_score = min(
            (ptrace_flag * 0.3 + rootkit_module_flag * 0.3 + mount_flag * 0.15 +
             priv_port_connect * 0.15 + (1.0 if sensitive_path_hits > 0 else 0.0) * 0.1),
            1.0
        )

        feat[120:128] = np.array([
            sens_path_norm, execve_norm, ptrace_flag, rootkit_module_flag,
            mount_flag, connect_rate, priv_port_connect, attack_surface_score
        ], dtype=np.float32)

        return np.nan_to_num(feat, nan=0.0, posinf=1.0, neginf=0.0)

    def extract_from_trace_numbers(self, seq: List[int], nr_map: Dict[int, str]) -> np.ndarray:
        """Fast extraction directly from syscall number sequences (ADFA-LD style)."""
        if not seq:
            return np.zeros(self.VECTOR_DIM, dtype=np.float32)

        feat = np.zeros(self.VECTOR_DIM, dtype=np.float32)
        n = len(seq)
        syscall_names = [nr_map.get(num, f"nr_{num}") for num in seq]

        # 1. 1-gram
        unigram_vec = np.zeros(50, dtype=np.float32)
        for s in syscall_names:
            idx = self.vocab.get(s, self.unk_idx)
            if idx < 50:
                unigram_vec[idx] += 1.0
        feat[0:50] = unigram_vec / max(n, 1)

        # 2. 2-gram
        bigram_vec = np.zeros(20, dtype=np.float32)
        if n >= 2:
            for i in range(n - 1):
                bg = f"{syscall_names[i]}->{syscall_names[i+1]}"
                if bg in self.bigram_vocab:
                    b_idx = self.bigram_vocab[bg]
                    if b_idx < 20:
                        bigram_vec[b_idx] += 1.0
            feat[50:70] = bigram_vec / max(n - 1, 1)

        # 3. 3-6 gram hash
        sids = [self.vocab.get(s, self.unk_idx) for s in syscall_names]
        ngram_hash_vec = np.zeros(20, dtype=np.float32)
        total_ngrams = 0
        if n >= 3:
            for k in (3, 4, 5, 6):
                if n >= k:
                    h = 0
                    mult = pow(31, k - 1, 1000000007)
                    for j in range(k):
                        h = (h * 31 + sids[j]) % 1000000007
                    ngram_hash_vec[h % 20] += 1.0
                    total_ngrams += 1
                    for i in range(1, n - k + 1):
                        h = ((h - sids[i - 1] * mult) * 31 + sids[i + k - 1]) % 1000000007
                        ngram_hash_vec[h % 20] += 1.0
                        total_ngrams += 1
        if total_ngrams > 0:
            feat[70:90] = ngram_hash_vec / total_ngrams

        # 4. Context defaults
        feat[90:100] = np.array([0.0, 0.0, 1.0, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.5], dtype=np.float32)

        # 5. Return value defaults
        feat[100:110] = np.array([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)

        # 6. Timing defaults (derived from trace length)
        log_dur = min(math.log10(max(n * 0.001, 1e-4) + 1.0) / 4.0, 1.0)
        log_count = min(math.log10(n + 1.0) / 5.0, 1.0)
        feat[110:120] = np.array([0.001, 0.0, 0.001, 0.001, 0.001, 0.5, 0.1, 0.0, log_dur, log_count], dtype=np.float32)

        # 7. Attack surface signals
        execve_count = sum(1.0 for s in syscall_names if s in ("execve", "execveat"))
        ptrace_flag = 1.0 if any(s == "ptrace" for s in syscall_names) else 0.0
        rootkit_flag = 1.0 if any(s in ("init_module", "finit_module") for s in syscall_names) else 0.0
        mount_flag = 1.0 if any(s == "mount" for s in syscall_names) else 0.0
        connect_count = sum(1.0 for s in syscall_names if s == "connect")

        feat[120:128] = np.array([
            0.0, min(execve_count / max(n, 1) * 5.0, 1.0), ptrace_flag,
            rootkit_flag, mount_flag, min(connect_count / max(n, 1) * 5.0, 1.0),
            0.0, min(ptrace_flag * 0.3 + rootkit_flag * 0.3 + mount_flag * 0.15, 1.0)
        ], dtype=np.float32)

        return np.nan_to_num(feat, nan=0.0, posinf=1.0, neginf=0.0)


def resolve_data_root(custom_root: Optional[Union[str, Path]] = None) -> Path:
    """Find valid ADFA-LD directory from candidates."""
    if custom_root and Path(custom_root).exists():
        return Path(custom_root)
    for c in DEFAULT_DATA_ROOT_CANDIDATES:
        if c.exists() and (c / "ADFA-LD+Syscall+List.txt").exists():
            return c
    # Fallback to first existing candidate
    for c in DEFAULT_DATA_ROOT_CANDIDATES:
        if c.exists():
            return c
    return DEFAULT_DATA_ROOT_CANDIDATES[0]


def main():
    parser = argparse.ArgumentParser(description="Host Feature Extractor (Person A - Week 5)")
    parser.add_argument("--root", default=None, help="Root path of ADFA-LD dataset")
    parser.add_argument("--test-sample", action="store_true", help="Run self-test on sample SyscallRecords")
    args = parser.parse_args()

    extractor = HostFeatureExtractor()
    print(f"[HostFeatureExtractor] Total feature dimensions: {extractor.VECTOR_DIM}")
    print(f"[HostFeatureExtractor] Feature names count: {len(extractor.FEATURE_NAMES)}")

    if args.test_sample or True:
        # Build synthetic test records
        sample_records = [
            SyscallRecord(timestamp=100.001, pid=1001, ppid=1, uid=0, comm="sh", syscall="openat", args={"filename": "/etc/shadow"}, ret=-13),
            SyscallRecord(timestamp=100.003, pid=1001, ppid=1, uid=0, comm="sh", syscall="connect", args={"ip": "192.168.1.50", "port": 4444}, ret=0),
            SyscallRecord(timestamp=100.008, pid=1001, ppid=1, uid=0, comm="sh", syscall="ptrace", args={"request": 16}, ret=0),
            SyscallRecord(timestamp=100.015, pid=1001, ppid=1, uid=0, comm="sh", syscall="execve", args={"filename": "/bin/bash"}, ret=0),
        ]
        vec = extractor.extract_from_records(sample_records)
        print(f"[Self-Test] Extracted vector shape: {vec.shape}, min: {vec.min():.4f}, max: {vec.max():.4f}, non-zero dims: {np.count_nonzero(vec)}")
        print(f"[Self-Test] Security indicators (120..127): {vec[120:128]}")


if __name__ == "__main__":
    main()
