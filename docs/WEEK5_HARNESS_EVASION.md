# Week 5 Harness Evasion Report

**Author:** Avinash (Person D — Adversarial Eval & Delivery)
**Date:** 2026-09-04

## 1. 128-D Feature Extractor Integration (Verified)
Tested Person A's new `HostFeatureExtractor` against the Week 4 `host_attack_story_trace.jsonl`.
- **Result:** SUCCESS. The generated trace is fully compatible with the new Pillar 3 schema. The extractor successfully parses all 167 records and outputs a valid 128-D `HostFeatureVector` with exactly 0 `NaN`s.

## 2. Host Autoencoder Integration (Blocked)
- **Status:** BLOCKED ON PERSON B.
- **Reason:** While Person B (Deep) has shipped a trained model (`host_autoencoder_adfa.pt`) and ablation study, their code (`exp_host_ablation.py`) relies on a simplified V+3 n-gram count vector, not Person A's rich 128-D `HostFeatureVector`. The actual `host_ae.py` model is still a "skeleton" that does not natively ingest the 128-D schema as claimed in the Week 5 Handover.
- **Action:** Adversarial scoring against the Host-AE is paused until Person B updates `host_ae.py` to accept the 128-D input vector.

## 3. Evasion Generator (Built)
Instead of fabricating scores against a model that isn't fully integrated, I built the evasion scenario **generator** only (`harness/host_evasion_variants.py`). It reads the verified trace and generates two bypass variants targeting specific feature blocks:
- **Variant 1 (Feature Padding):** Floods the trace with benign `openat`/`close` calls to suppress the relative frequency of critical syscalls, aiming to bypass the 1-Gram Block.
- **Variant 2 (Timing Morph):** Stretches inter-arrival timestamps to bypass the Timing Dynamics block (burstiness, mean/std $\Delta t$).

## 4. 3-Pillar Dashboard Fusion (Built)
Added a "3-Pillar Fusion Analysis" card to the SOC dashboard UI (`dashboard/`).
- Updated `dashboard/index.html` to display Network (P1), Identity (P2), and Host Syscall (P3) sub-scores, along with an Ensembler combined confidence.
- Modified `dashboard/app.js` to render the fusion metrics.
- Updated `dashboard/sampleData.js` with simulated payloads mapping my kill-chain's ATT&CK techniques (`T1204.002`, `T1055.008`, `T1547.006`, `T1071.001`) into the fusion context. Network and Identity scores are stubbed/simulated to highlight the critical Host signal.
