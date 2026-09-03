# Red-Team Evasion Evaluation Harness

This framework implements and evaluates adversarial evasion techniques and multi-stage attack scenarios targeting our anomaly detection pillars (Pillar 1: Network Flow, Pillar 2: Identity UEBA, Pillar 3: Host eBPF Syscalls).

## Structure & Modules

### 1. Host Attack Kill-Chain Spec (Week 4 — Pillar 3)
- [`host_attack_scenario.py`](host_attack_scenario.py): Implements "Operation SilentWhisper", a replayable 5-stage stealth attack scenario (`phishing email → dropper execve → process injection via ptrace → credential dumping → HTTPS C2 exfiltration`). Conforms to the 8 hooked eBPF tracepoints and outputs replayable `SyscallRecord` streams.
- Complete design doc and blind-spot rationale: [`docs/HOST_ATTACK_SCENARIO.md`](../docs/HOST_ATTACK_SCENARIO.md).

### 2. Relational GNN Evasion Harness (M5b)
- [`run_graph_harness.py`](run_graph_harness.py): Evaluates evasion resistance of the Graph Autoencoder (M5b) against `slow_scan`, `distributed_scan`, `cover_traffic`, and `port_narrowing`.
- [`graph_techniques.py`](graph_techniques.py): Implementation of graph-level adversarial techniques.

### 3. Baseline Flow Autoencoder Evasion Harness (M5a — Checkpoint-1)
- [`run_harness.py`](run_harness.py): The entry point orchestrating benchmark runs against the baseline autoencoder model (M5a).
- [`techniques.py`](techniques.py): Implements three per-flow evasion algorithms:
  - **Mimicry Attack**: Linearly interpolates from a malicious vector toward a benign reference.
  - **Feature Padding**: Interpolates only the top 10 features with the highest absolute deviation.
  - **Slow-Drip**: Simulates flow partitioning over smaller splits.
- [`utils.py`](utils.py): Normalizes normal flows using CICIDS2017 features and generates synthetic malicious samples.
- [`diagnose_features.py`](diagnose_features.py): Diagnoses individual feature contribution to reconstruction error.

## Running Evaluations

### Host Attack Scenario Generator (Pillar 3 Replayable Trace):
```bash
python harness/host_attack_scenario.py
```

### Relational Detector Harness (M5b):
```bash
python harness/run_graph_harness.py
```

### Flow Baseline Harness (M5a / Checkpoint-1):
```bash
$env:PYTHONIOENCODING="utf-8"
python harness/run_harness.py
```

## Results Logs (`harness/results/`)

- [`host_attack_story_trace.jsonl`](results/host_attack_story_trace.jsonl): Replayable 166-event stream conforming to `SyscallRecord`.
- [`host_attack_story_summary.json`](results/host_attack_story_summary.json): Stage metadata, ATT&CK mappings, and P1/P2 blindness rationales.
- [`autoencoder_v2_baseline.csv`](results/autoencoder_v2_baseline.csv) & [`autoencoder_v2_baseline_v2.csv`](results/autoencoder_v2_baseline_v2.csv): Checkpoint-1 baseline evasion logs.
- [`m5b_evasion.csv`](results/m5b_evasion.csv), [`m5b_evasion.json`](results/m5b_evasion.json), [`m5b_evasion.md`](results/m5b_evasion.md): M5b graph evasion benchmark results.
