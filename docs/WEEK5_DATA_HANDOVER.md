# 📊 Week 5 Data Handover: Host Telemetry & Held-Out Attack-Family Protocol

> [!NOTE]
> **Author:** Saharsh (Person A — Data & Capture / Host Telemetry)  
> **Audience:** Person B (Detector Modeling), Person C (SHAP & ATT&CK Mapper), Person D (Adversarial Eval & Harness)  
> **Scope:** Multi-Modal Host Feature Extraction (128-D) + Held-Out Attack-Family Zero-Day Evaluation Protocol  
> **Artifact Path:** `docs/WEEK5_DATA_HANDOVER.md`

---

## 🧭 Executive Summary

During **Week 5**, Person A expanded the telemetry pipeline from network-only monitoring to a **unified dual-plane capture layer (Network Flows + Host Syscalls)**. In accordance with the project roadmap and empirical findings by *Guo et al. (2024)*, raw syscall names alone are insufficient for zero-day detection. This handover establishes:

1. **Rich Multi-Modal Host Feature Extractor (`capture/host_feature_extractor.py`)**: A 128-dimensional fixed-length `HostFeatureVector` capturing n-grams (1–6), process tree context, return-value distributions, inter-arrival timing dynamics, and critical attack-surface indicators.
2. **Standardized JSON Schemas**:
   - `schemas/syscall_record.json`: Standard schema for raw/replayed eBPF syscall events.
   - `schemas/host_feature_vector.json`: Standard schema for the 128-dimensional Host FeatureVector block.
3. **Held-Out Host Attack-Family Zero-Day Protocol (`detection/host_held_out_protocol.py`)**: A rigorous zero-day evaluation benchmark trained strictly on benign baseline traces and tested against 6 unseen host attack families (`Adduser`, `Hydra_FTP`, `Hydra_SSH`, `Java_Meterpreter`, `Meterpreter`, `Web_Shell`).

---

## 🏗️ 1. Host Feature Architecture (128 Dimensions)

The 128-dimensional `HostFeatureVector` is partitioned into 7 functional blocks:

```
+──────────────────────────────────────────────────────────────────────────────────────────────────+
|                                128-DIM HOST FEATURE VECTOR                                       |
+─────────────────────────┬─────────────────────────┬─────────────────────────┬────────────────────+
| 0..49 (50 dims)         | 50..69 (20 dims)        | 70..89 (20 dims)        | 90..99 (10 dims)   |
| Top-49 Pinned Unigrams  | Top-20 Pinned Bigrams   | 3..6-gram Hashed Motifs | Process Context    |
| + UNK Syscall Bin       | Transition Probabilities| Sequence Signature      | (PID/UID/Comm/Tree)|
+─────────────────────────┼─────────────────────────┴─────────────────────────┴────────────────────+
| 100..109 (10 dims)      | 110..119 (10 dims)      | 120..127 (8 dims)                            |
| Return-Value / Errno    | Inter-Syscall Timing    | Security Indicators & Attack Surface         |
| (EPERM/ENOENT/EACCES)   | (Burstiness, Δt Stats)  | (ptrace, rootkit modules, sensitive paths)   |
+─────────────────────────┴─────────────────────────┴──────────────────────────────────────────────+
```

### Dimensional Breakdown

| Block | Dim Range | Count | Key Features / Metrics | Downstream Utility |
|---|---|---|---|---|
| **1-Gram Unigrams** | `0..49` | 50 | Pinned top benign unigrams + UNK mass | Syscall frequency baseline (M5a-H) |
| **2-Gram Bigrams** | `50..69` | 20 | Consecutive syscall transition pairs | Detects broken execution sequences |
| **Higher-Order N-Grams** | `70..89` | 20 | 3-gram to 6-gram hashed sliding windows | Captures multi-step malicious motifs |
| **Process Context** | `90..99` | 10 | `is_root`, `uid_changes`, `comm_entropy`, `spawn_rate`, `orphan_rate` | Catches privilege escalation & shell execution |
| **Return Distributions** | `100..109` | 10 | `success_rate`, `error_rate`, `EPERM`, `ENOENT`, `EACCES`, `err_entropy` | Detects reconnaissance & failed file probing |
| **Timing Dynamics** | `110..119` | 10 | Mean/Std/Min/Max $\Delta t$, burstiness, event rate, duration | Identifies automated exploits vs interactive shells |
| **Security Indicators** | `120..127` | 8 | Sensitive path hits (`/etc/shadow`, etc.), `ptrace`, `init_module`, `mount`, port $< 1024$ | Hard signal for process injection & rootkits |

---

## 🧪 2. Zero-Day Held-Out Evaluation Protocol

### Protocol Rules & Integrity Constraints:
1. **Benign-Only Training**: The detection models (Host AE / Subspace Anomaly Detectors) are fitted **only** on benign baseline data (`Training_Data_Master`, 833 traces).
2. **Threshold Calibration**: The anomaly score threshold is locked on a 50% split of `Validation_Data_Master` at fixed target False Positive Rates ($\text{FPR} \le 1.0\%$ and $\text{FPR} \le 0.1\%$).
3. **Unseen Attack Family Testing**: Each attack family is evaluated as a true zero-day scenario (never seen during training or threshold calibration).

### Attack Families Evaluated (ADFA-LD):

| Attack Family | Trace Count | Kill-Chain Stage & MITRE Technique | Primary Signal Channels |
|---|---|---|---|
| **`Adduser`** | 91 | Unauthorized Account Creation (`T1136.001`) | Sensitive path hits (`/etc/passwd`), `setuid`, high error entropy |
| **`Hydra_FTP`** | 162 | Network Credential Brute-Force (`T1110`) | Inter-syscall timing burstiness, repeated network reconnects |
| **`Hydra_SSH`** | 176 | SSH Credential Brute-Force (`T1110`) | High-frequency `clone`/`execve`, socket resets |
| **`Java_Meterpreter`** | 124 | Memory-Only Exploit & C2 Payload (`T1059.007`) | Elevated syscall entropy, non-standard bigram transitions |
| **`Meterpreter`** | 75 | In-Memory Shellcode & C2 Agent (`T1055`) | `ptrace` usage, memory mapping changes, 3-6 gram hash deviations |
| **`Web_Shell`** | 118 | Web Application Command Execution (`T1505.003`) | Web server process spawning shell binaries (`sh`, `bash`, `nc`) |

---

## 🤝 3. Team Contracts & Integration Boundaries

### For Person B (Detection Modeling — Deep):
- **Model Input**: Consume the 128-dimensional vector produced by `capture/host_feature_extractor.py` or the pinned count vector in `detection/host_features.py`.
- **Model Architecture**: The Host Autoencoder `HostAutoencoder(128 -> 64 -> 32 -> 16 -> 8 -> 16 -> 32 -> 64 -> 128)` natively ingests this vector.
- **Ablation Protocol**: Use `detection/host_held_out_protocol.py` to report held-out family generalization.

### For Person C (SHAP Explainer & ATT&CK Mapper — Aditya):
- **Feature Names**: Use `HostFeatureExtractor.FEATURE_NAMES` for direct SHAP attribution.
- **Rule Engine Mapping**: Map features `120..127` and process context `90..99` directly into MITRE ATT&CK technique IDs in `detection/attack_mapper_full.json`.

### For Person D (Harness & Adversarial Evaluation — Avinash):
- **Trace Replay**: Person D can stream synthetic traces from `harness/host_attack_scenario.py` directly into `HostFeatureExtractor.extract_from_records()` without schema mismatch.
- **Reconciliation**: All 12 hooked syscalls (`open`, `openat`, `execve`, `execveat`, `connect`, `setuid`, `setgid`, `setresuid`, `ptrace`, `clone`, `init_module`, `mount`) are fully supported.

---

## 🚀 4. How to Run

```bash
# 1. Self-test feature extraction & print 128-dim vector
python capture/host_feature_extractor.py --test-sample

# 2. Run the complete Held-Out Host Attack-Family Zero-Day Benchmark
python detection/host_held_out_protocol.py --out detection/held_out_host_results.json

# 3. View extracted dataset stats & pinned vocabularies
python detection/host_features.py
```
