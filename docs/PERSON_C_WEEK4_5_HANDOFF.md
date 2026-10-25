# Person C handoff: Weeks 4–5 inputs and integration

**Owner:** Person C — Trust & Risk  
**Audience:** Person A (Data & Capture), Person B (Detection Modeling), Person D (Eval & Delivery)  
**Purpose:** Make the completed mapper/interface work and the remaining cross-person handoffs explicit before Week 6 integration.

## Person C work delivered

- Week 4 host ATT&CK candidates are implemented in `detection/host_syscall_mapper.py`, backed by `attack_mappers/host_syscall_attack_mapper.json`. The mapper requires evidence for a candidate and does not treat a single `openat` event as proof of T1486.
- Week 5 host reconstruction-SHAP interface is `detection/host_shap_explainer.py`. It requires model-ready samples and benign background vectors using the model's exact feature order and scaling.
- Week 5 risk-fusion interface is `detection/risk_fusion.py`. It accepts normalized network, identity, and host scores and a fitted/calibrated positive-class predictor. It does not train that predictor or invent its calibration.
- Week 6 alert fields are specified in `schemas/scored_alert.json`. The fusion builder emits nested `pillar_scores` plus `network_score`, `identity_score`, and `host_score` aliases for the dashboard's existing detail view. It strips known raw host-identity keys and excludes raw values from SHAP output.

These components have focused unit tests. They are interfaces and isolated checks, not evidence of real host-model performance or a complete live deployment.

## Required handoffs

### Person A — capture and feature contract

Please provide or confirm:

1. A representative benign host background matrix and labelled/replay samples, with source and split information.
2. The exact host feature dimension, feature order, and preprocessing/scaling used for those samples.
3. Confirmation that the stream includes the syscall/endpoint evidence required by the host ATT&CK rules, or a list of unavailable telemetry.

The current `HostFeatureExtractor` contract is 128-D. Do not send raw host identifiers, process names, command lines, or paths to the shared alert payload.

### Person B — host detector

Please provide or confirm:

1. The production host checkpoint and its expected input dimension, feature order, and scaler state.
2. A host anomaly score and threshold/calibration semantics for replayed samples.
3. A small labelled set of host scores aligned by event/window with the network and identity scores for risk-model training and calibration.

There is a dimension mismatch to resolve before real host SHAP: the available `host_autoencoder_adfa.pt` is 153-D, while the current host feature handover is 128-D. Do not pair them until B confirms a compatible representation.

### Person D — alert consumer

Please confirm the API/dashboard accepts the Week 6 payload fields:

- `pillar_scores`: `{network, identity, host}` normalized values in `[0, 1]`.
- Compatibility aliases: `network_score`, `identity_score`, `host_score`.
- `risk_probability` and `risk_model_source`.
- Optional `host_attack_mappings` / `host_mapping_status` and `host_shap_features`.

The current dashboard detail view reads the three top-level score aliases. The static preview does not by itself validate the live API path.

## Week 6 integration gates

1. Freeze the payload contract with A/B/D; keep existing required `ScoredAlert` fields unchanged.
2. Validate all host telemetry is minimized before serialization. Never include raw UID/PID/PPID, `comm`, command arguments, process paths, or sensitive file paths in the shared alert.
3. Once A/B provide compatible host data and scores, run real host SHAP and a calibrated-fusion validation using held-out data.
4. Have D replay a representative payload through the API/dashboard and verify all three pillar values, risk probability, ATT&CK candidates, and SHAP feature names render.

Until those inputs and checks are complete, describe Week 4 mapper work and Week 5 interfaces as implemented, with real host SHAP/fusion integration pending—not as validated production detections.
