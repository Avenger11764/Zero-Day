# Interface Request to Person B: 128-D Host Autoencoder & Scoring Interface

**From:** Avinash (Person D — Adversarial Eval & Delivery)  
**To:** Deep (Person B — Detection Modeling)  
**Date:** 2026-10-29  
**Status:** BLOCKED — Awaiting 128-D Host Model / Checkpoint  

---

## 1. Problem Statement & Context

In Week 5, Person A delivered the multi-modal 128-dimensional host feature extractor (`capture/host_feature_extractor.py`) according to the project roadmap and `schemas/host_feature_vector.json`.

However, host adversarial evaluation in Person D's harness (`harness/run_host_evasion.py`) is currently blocked:
- `detection/host_autoencoder_adfa.pt` expects a 153-D count vector ($V+3$ format via `detection/host_features.py`).
- `detection/host_ae.py` remains an un-updated 32-D synthetic skeleton.
- Neither model ingests Person A's standardized 128-D `HostFeatureVector`.

Per our evaluation methodology (and the lesson from the Week 3 bug), I will **not** force our 12-syscall kill-chain trace into the ADFA $V+3$ format, as that would generate fabricated scores that do not reflect real detection or evasion.

---

## 2. Exact Input Specification Needed

- **Vector Dimension:** Exactly 128 continuous float features (`shape: (128,)` or batch `(N, 128)`).
- **Feature Schema:** Defined in `schemas/host_feature_vector.json` (Blocks 0..49: unigrams, 50..69: bigrams, 70..89: n-gram hash motifs, 90..99: process context, 100..109: return distribution, 110..119: timing dynamics, 120..127: security indicators).
- **Feature Extractor:** `capture/host_feature_extractor.HostFeatureExtractor(dimension=128)` extracts this vector directly from `SyscallRecord` streams.
- **Normalization / Scaling:** Model must provide an associated `HostScaler` (or scaler parameters `lo`, `hi`, `log`) fitted on benign 128-D baseline data.

---

## 3. Test Trace Files

To test and calibrate the model, use the verified Week 4-5 kill-chain traces:
1. **Baseline Kill-Chain Trace (Unmodified):**  
   `harness/results/host_attack_story_trace.jsonl` (167 records, 17 attack events across 5 kill-chain stages).
2. **Adversarial Variant 1 (Feature Padding):**  
   `harness/results/evasion_variants/variant_padding.jsonl` (padding benign `openat`/`close` calls to evade unigram frequency).
3. **Adversarial Variant 2 (Timing Morph):**  
   `harness/results/evasion_variants/variant_timing.jsonl` (stretched inter-arrival timestamps to evade timing dynamics).

---

## 4. Required Output Contract

To unblock automated scoring in `harness/run_host_evasion.py`, Person D needs:
1. **Checkpoint:** A saved PyTorch model checkpoint (e.g. `detection/host_autoencoder_128d.pt` or updated `detection/host_autoencoder.pt`) with `input_dim=128`.
2. **Scaler:** Saved scaler state dict or parameters compatible with 128 dimensions.
3. **Calibrated Threshold:** A concrete decision threshold $\tau \in \mathbb{R}^+$ calibrated on benign validation data (e.g., at 99th percentile or target $1\%$ FPR).
4. **Scoring Seam:** A callable function or model method:
   ```python
   def score_host_vector(vector_128d: np.ndarray) -> dict:
       # returns {"anomaly_score": float, "threshold": float, "flagged": bool}
   ```

Once delivered, `harness/run_host_evasion.py` will immediately execute and produce verified evasion resistance metrics (`host_evasion_results.csv` and `.md`).
