# Person C — Weeks 4–6 work summary and team handoff

**Owner:** Aditya — Person C, Trust & Risk  
**Purpose:** Explain what Person C has implemented, what has been tested, what remains, and the concrete inputs needed from the other team members.

## Executive summary

Person C has implemented and tested the host-side ATT&CK mapping component, prepared interfaces for host SHAP and three-pillar risk fusion, and extended the shared alert contract and dashboard detail view for Week 6.

The work is **not yet an end-to-end live three-pillar integration**. In particular, no real host SHAP result or calibrated three-pillar risk result has been demonstrated. Those require a compatible host checkpoint and host vectors from A/B, aligned labelled pillar scores and a trained/calibrated risk model, and the live API handoff from D. Dashboard verification so far used a synthetic browser payload; visible dashboard alerts are static preview examples.

## How the components fit together

Think of the three detection pillars as separate sensors:

- **Pillar 1 — Network:** observes flow behaviour.
- **Pillar 2 — Identity:** observes user/account behaviour.
- **Pillar 3 — Host:** observes process and syscall behaviour.

Person C's components are the interpretation and reporting layer:

1. The **ATT&CK mapper** looks for evidence-backed host activity patterns and reports technique candidates.
2. **SHAP** describes which model input features contributed to an anomaly score.
3. **Risk fusion** accepts the three pillar scores and asks an already-trained/calibrated model for one overall risk probability.
4. The **unified alert** carries these optional details in the shared `ScoredAlert` shape for the dashboard/API to consume.

These pieces do not replace the detectors, collect telemetry, train the host autoencoder, or train the risk model.

## Week 4 — Host syscall ATT&CK mapper

### Implemented

- `detection/host_syscall_mapper.py` combines a host score, a threshold supplied by the detector owner, syscall/endpoint events, and named host features.
- `attack_mappers/host_syscall_attack_mapper.json` stores the host syscall/endpoint mapping catalogue, separate from network and UEBA mapper data.
- The mapper returns a status (`below_threshold`, `no_match`, or `candidate`) and ATT&CK candidates with evidence, completeness, matched feature names, and limitations.
- Example mappings include paired `ptrace` and `process_vm_readv` evidence for T1055.008; `OpenProcess` targeting LSASS together with `MiniDumpWriteDump` for T1003.001; startup registry writes for T1547.001; module loading for T1547.006; and evidence-qualified privilege transitions for T1548.001.
- `openat` activity by itself does **not** trigger T1486: file-write/change evidence is needed to distinguish encryption from ordinary file access.
- Evidence text avoids echoing concrete process IDs, registry paths, and module names. The mapper does not treat a mapping candidate as proof of an attack.

### Validation and boundary

The mapper has focused unit tests. It is available as a callable enrichment seam, but is not wired into B's production alert pipeline because that producer does not yet supply the host score and host telemetry required by the mapper.

**Week 4 status:** Person C's mapper implementation and isolated tests are done; live pipeline integration waits for the host detector/capture handoff.

## Week 5 — Host SHAP and risk fusion

### Host SHAP interface

`detection/host_shap_explainer.py` explains a reconstruction-error autoencoder score. It accepts:

- model-ready sample vectors,
- a benign background matrix,
- feature names matching the exact model input order and scaling, and
- an autoencoder whose output dimension matches its input.

It returns the anomaly score, baseline value, and highest-impact feature names with contribution directions. It intentionally omits the raw feature values so attributions can be included in a minimized alert.

The interface is tested using a small mock autoencoder. It has **not** yet generated a verified explanation from real host traces and the available production host checkpoint.

### Risk-fusion interface

`detection/risk_fusion.py` accepts normalized network, identity, and host scores in `[0, 1]` and a predictor that has already been trained and calibrated. It checks for the positive class and a valid probability result, then builds a unified alert.

It does **not** fit the model, calibrate it, or invent weights. The current tests use a fixed mock predictor to verify the interface only; they are not evidence that a trained risk model is accurate.

### Current compatibility/data blocker

- The host feature handover describes a 128-dimensional `HostFeatureExtractor` representation.
- The available `detection/host_autoencoder_adfa.pt` checkpoint is documented as expecting 153 inputs.
- Feature count alone is insufficient: feature order, preprocessing, and scaler must also match. Do not feed the 128-D vectors into that checkpoint or claim real host SHAP until B confirms or supplies a compatible model/input contract.
- The local `data/` inventory checked for this work contained CICIDS network CSVs, not the ADFA-LD/LID-DS host traces or aligned labelled network/identity/host risk-training rows.

**Week 5 status:** SHAP and fusion interfaces plus mock/interface tests are done. Real host SHAP, fusion training/calibration, and performance claims are pending compatible model/data handoffs.

## Week 6 — Unified alert, privacy, and dashboard details

### Implemented

- `schemas/scored_alert.json` has optional fields for host mapping, grouped pillar scores, top-level pillar-score compatibility fields, calibrated risk probability/model source, and host SHAP features. Existing required alert fields remain unchanged.
- The alert builder emits both `pillar_scores: {network, identity, host}` and `network_score`, `identity_score`, `host_score` because the existing dashboard reads the top-level form.
- The builder removes known host identity/event fields recursively and emits only SHAP feature names, numeric contributions, and direction—not raw SHAP input values.
- `dashboard/app.js` and `dashboard/index.html` display grouped or top-level pillar scores, host ATT&CK candidates/evidence, and host SHAP contributions in the alert detail drawer.
- Dynamic host mapping/SHAP details are inserted as text, not interpreted as HTML.
- `dashboard/README.md` documents the fields and clarifies that the dashboard is still in static preview mode.

### What was actually verified

- A local browser test passed a **synthetic test alert** to the drawer and confirmed all three pillar values, risk probability, an ATT&CK candidate, and one SHAP feature rendered.
- The synthetic browser payload was used only for the UI test; it was not added to the dashboard's static dataset.
- The dashboard's visible sample alerts are not live API detections. `dashboard/sampleData.js` supplies static preview data with illustrative IP addresses/timestamps.
- The API/WebSocket is not connected or validated in this work.

**Week 6 status:** payload/schema and dashboard rendering groundwork are implemented and locally UI-tested. Live API-to-dashboard integration and real host alert replay remain pending.

## Validation performed

- Full Python unit test suite: **16 tests passed**.
- Focused Week 6 fusion and Week 4 mapper tests passed.
- `node --check dashboard/app.js`: passed.
- `jq empty schemas/scored_alert.json`: passed.
- `git diff --check`: passed.
- Host SHAP tests use a mock model; the browser integration check uses a synthetic payload. Neither should be reported as real host detection performance.
- Network SHAP was separately smoke-tested on available CICIDS data; one seeded benign example scored `0.000374`, and a 20-row PortScan sample had 3 rows above the existing threshold. This was a smoke test only, not a performance evaluation or threshold recalibration.

## Handoff requests

### Person A — Data & Capture

Please provide or confirm:

1. A small benign host background set and representative labelled/replay host windows, with dataset source and train/validation/test split.
2. The exact vector dimension, ordered feature names, and preprocessing/scaling used for those vectors.
3. Which syscall/endpoint fields are actually present in replay, especially the evidence needed by the host ATT&CK catalogue.
4. Confirmation of the privacy-safe fields that may cross into a shared alert. Raw UID/PID/PPID, `comm`, command lines, and sensitive paths must not be included.

### Person B — Detection Modeling

Please provide or confirm:

1. Which host checkpoint is the intended model, its expected dimension and feature order, and the scaler state needed to reproduce scores.
2. Whether the 153-D ADFA checkpoint is compatible with any supplied feature producer, or provide a model matching A's 128-D contract.
3. The host score semantics and threshold/calibration protocol for replayed samples.
4. Once host scoring is available, a small event/window-aligned table of network, identity, and host scores with labels and split IDs. This is required before Person C can train and calibrate risk fusion without leakage.

### Person D — Evaluation & Delivery

Please confirm the API/WebSocket consumer contract and provide a route or test fixture for replaying one alert through the real consumer. The expected optional alert fields are:

- `pillar_scores` and/or `network_score`, `identity_score`, `host_score`;
- `risk_probability` and `risk_model_source`;
- `host_mapping_status`, `host_attack_mappings`, and `host_explanation`;
- `host_shap_features`.

Please verify how the API/dashboard should represent missing pillar values and whether host details need any additional display or access controls.

## Suggested next sequence

1. A and B resolve the host feature/checkpoint compatibility and provide a small host replay plus model scoring handoff.
2. Person C runs SHAP using the matching feature names, scaler, and benign background; validates mapper evidence on the replay; then records the limits of the result.
3. A/B/C assemble event-aligned labelled scores with a leakage-safe split. Person C fits/calibrates the risk model only after this dataset exists and evaluates it on held-out data.
4. D connects the API/WebSocket to the dashboard and replays a representative real alert payload.
5. The team checks privacy on the serialized payload and records end-to-end validation results before marking Week 6 complete.

## Run the current tests

From the repository root, using the configured project environment:

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python -m unittest discover -s tests -v
node --check dashboard/app.js
jq empty schemas/scored_alert.json
```

These commands verify the current interfaces and dashboard syntax/schema. They do not train the missing models or connect a live API.
