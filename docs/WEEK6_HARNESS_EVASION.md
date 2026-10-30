# Week 6 Harness Evasion & Delivery Report

**Author:** Avinash (Person D — Adversarial Eval & Delivery)  
**Date:** 2026-10-29  
**Status:** Complete (Delivery & Evaluation Primed; Host Scoring Blocked on Person B)  

---

## 1. Executive Summary & Week 6 Scope

During Week 5 and 6, Role D focused on unblocking host-based adversarial scoring, establishing the hardening-loop export pipeline, hardening documentation, and refreshing the SOC dashboard snapshot from real evaluation outputs.

The primary deliverable—evaluating host evasion variants against Person B's Host Autoencoder—remains **blocked under Case B** because Person B's deployed models (`detection/host_autoencoder_adfa.pt` and `host_ae.py`) accept only 153-D ($V+3$) or 32-D inputs, rather than Person A's standardized 128-D `HostFeatureVector`. In accordance with our core methodological rule (learned from Week 3), we refuse to fabricate scores or force our 12-syscall trace into an incompatible format.

---

## 2. Deliverables & What Was Done

### 2.1 Housekeeping & Documentation Fixes (Task 1)
- Re-encoded `docs/WEEK5_HARNESS_EVASION.md` from malformed UTF-16 back to clean UTF-8. Preserved all original text and fixed the creation date to `2026-10-01`.
- Cleaned absolute local paths (`file:///d:/...`) in `dashboard/README.md`, replacing them with portable relative links.

### 2.2 Host Evasion Scoring & Case B Interface Request (Task 2)
- Implemented `harness/run_host_evasion.py`:
  - Automatically extracts 128-D `HostFeatureVectors` for the original kill-chain trace and both adversarial evasion variants (`variant_padding.jsonl` and `variant_timing.jsonl`) using Person A's `HostFeatureExtractor`.
  - Verifies zero NaNs and valid dimensional boundaries across all traces.
  - Implements an explicit compatibility guard: inspects model input dimensions and exits cleanly if `n_dim != 128`.
  - Encodes the methodological rule: confirms the baseline trace is flagged before measuring evasion; reports `"baseline trace not detected, evasion not measurable"` if unflagged.
- Created `docs/REQUEST_TO_PERSON_B.md`:
  - Half-page formal interface request to Person B (Deep).
  - Specifies the exact input shape (128-D float vector per `schemas/host_feature_vector.json`), test trace files (`host_attack_story_trace.jsonl`), required scaler configuration, and output scoring contract (anomaly score + calibrated decision threshold).

### 2.3 Adversarial Hardening-Loop Exporter (Task 3)
- Created `harness/export_evaded_for_retraining.py`:
  - Automated scaffold to export evaded adversarial samples into `harness/results/hardening_export/`.
  - Strict guard: Performs **export only** without retraining or altering any model.
  - Handles Case B fallback: because host scoring is blocked, it captures real network-side evaded configurations from `harness/results/m5b_evasion.json` (6 configurations from `slow_scan` and `distributed_scan` that bypassed M5b's 99th percentile threshold) and `autoencoder_v2_baseline_v2.csv`.
  - Validates schema compatibility and outputs `evaded_network_samples.json` along with `export_manifest.json`, clearly labeled as `adversarial`.

### 2.4 Dashboard Snapshot Generator (Task 4)
- Created `harness/build_dashboard_snapshot.py`:
  - Regenerates `dashboard/sampleData.js` from real result files (`host_attack_story_summary.json` and `m5b_evasion.csv`).
  - Strict boundary: snapshot only; no `fetch()`, no WebSocket, and no live backend.
  - Maintained honest labeling: real measured network evasion values are badged as `MEASURED_NET`, while kill-chain host and identity sub-scores are explicitly labeled as `STAGED_HOST` / `STAGED_PREVIEW` with detailed transparency notes.
  - Updated `dashboard/app.js` table rendering to support badge text (`alert.badge_text`), ensuring the dashboard never mispresents staged values as measured numbers.

---

## 3. Real Numbers vs. Staged Data

| Metric / Component | Value / Result | Source File | Status |
|---|---|---|---|
| **Host Feature Extraction** | 128 dimensions, 0 NaNs | `capture/host_feature_extractor.py` | **MEASURED** (Verified) |
| **Padding Variant Trace** | 337 syscall records | `harness/results/evasion_variants/variant_padding.jsonl` | **MEASURED** (Generated) |
| **Timing Morph Variant** | 167 syscall records | `harness/results/evasion_variants/variant_timing.jsonl` | **MEASURED** (Generated) |
| **Host Model Anomaly Score** | N/A (Blocked) | `detection/host_ae.py` | **BLOCKED (Case B)** |
| **Host Calibrated Threshold** | N/A (Blocked) | `detection/host_autoencoder_adfa.pt` (153-D) | **BLOCKED (Case B)** |
| **Network M5b Slow-Scan Evasion** | Score 0.000661 vs thr 0.000924 | `harness/results/m5b_evasion.csv` | **MEASURED** (Real) |
| **Network M5b Dist-Scan Evasion** | Score 0.000211 vs thr 0.000924 | `harness/results/m5b_evasion.csv` | **MEASURED** (Real) |
| **Identity (P2) Sub-Scores** | Staged illustrative (0.00 - 0.65) | `dashboard/sampleData.js` | **STAGED / SIMULATED** |
| **Kill-Chain Host Sub-Scores** | Staged preview (0.88 - 0.99) | `dashboard/sampleData.js` | **STAGED / SIMULATED** |

---

## 4. Open Items & Handoff Requests

1. **Person B (Detection Modeling):**
   - Provide a trained 128-D Host Autoencoder checkpoint (e.g. `detection/host_autoencoder_128d.pt`) and fitted `HostScaler` state matching `schemas/host_feature_vector.json`.
   - Provide the calibrated decision threshold $\tau$ (e.g. 99th percentile on benign validation).
   - Once delivered, running `python harness/run_host_evasion.py` will immediately score all variants and generate `harness/results/host_evasion_results.csv`.
2. **Person C (Trust & Risk):**
   - Person D's dashboard and snapshot schemas now fully reflect Person C's `ScoredAlert` extensions (`pillar_scores`, `host_attack_mappings`, `host_shap_features`).
   - Awaiting calibrated 3-pillar risk model probability once Person B supplies aligned scores.
3. **Person D (Next Steps for Week 6 Demo Delivery):**
   - Record the end-to-end demo video once Person B unblocks the 128-D host model.
   - Prepare presentation slides reflecting the measured network evasion results and host resistance metrics.
