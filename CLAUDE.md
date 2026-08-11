# Zero-Day Detection FYP — agent context

Read this first, then the top of `CHANGELOG.md` for what changed most recently.

## Who you're working with

**Deep** — Person B on a four-person final-year project, owning **Detection
Modeling**. Not the data person, not the explainability person, not the demo
person. When work drifts into another vertical, say so rather than silently
doing it.

| Member | Track | Owns |
| --- | --- | --- |
| A — Saharsh | Data & Capture | flow capture, feature engineering, dataset prep, `FlowRecord` |
| **B — Deep** | **Detection Modeling** | **baseline AE, GNN-temporal, drift monitor, ensembler** |
| C — Aditya | Trust & Risk | SHAP, learned UEBA risk model, ATT&CK mapper, privacy pass |
| D — Avinash | Adversarial Eval & Delivery | red-team harness, FastAPI + React dashboard, alert API |

Deep's individually-attributable headline result is **the baseline-vs-GNN
ablation** — the controlled comparison, not "we built a GNN".

## The project in one line

Learn what normal network behaviour looks like, flag deviations, explain why,
notice when "normal" drifts, and actively try to evade it. Three pillars:
network flow (Pillar 1, Deep's), identity UEBA (Pillar 2), host syscalls via
eBPF (Pillar 3, weeks 4–6).

Reference material lives in `Knowledge/` — **local only, gitignored, never
push it.** It holds the full spec PDF and the weeks 4–6 roadmap.

## Hard-won gotchas — do not rediscover these

1. **`venv/` is never portable.** It embeds absolute paths. The repo arrived
   with a venv pointing at `C:\Users\trex2\...` and nothing could run. Each
   machine builds its own from `requirements.txt`. Never commit it.

2. **Never hardcode an absolute path.** Four scripts were pinned to
   `D:\Test OD\Zero-Day\...`. Everything now resolves via
   `Path(__file__).resolve().parent...`. Keep it that way.

3. **Two CICIDS2017 releases, and only one can build a graph:**
   - `data/MachineLearningCSV/` — 79 cols, **no IP columns at all**. Fine for
     the per-flow baseline, useless for graphs.
   - `data/GeneratedLabelledFlows/TrafficLabelling/` — 85 cols, **has Flow ID,
     Source IP, Destination IP, Protocol, Timestamp**. Required for anything
     relational. These files are **latin-1, not UTF-8** — use
     `graph_builder.read_flows()`.

4. **`Destination Port` IS one of the 76 model features**, not metadata — in
   the CICIDS2017 releases. A's CICFlowMeter output treats it as metadata
   instead. Both conventions are handled; don't "simplify" that away.

5. **Never derive feature columns per-file with `dropna(axis=1)`.** It drops
   different columns on different attack days and hands the model misaligned
   features. Scores look plausible and mean nothing. Pin the column list once
   from the training file (`ensembler.pin_canonical`).

6. **A's synthetic datasets cannot form graphs.** `dataset_10k_normal.csv` has
   508 clients all touching the identical 2 services (every neighbourhood is
   the same → embeddings collapse). `live_capture.csv` has `dst_port` as an
   incrementing counter → 12,503 services across 12,504 flows. Use
   `graph_builder.graph_health()` before training on any new source.

7. **`DEFAULT_THRESHOLD = 0.5` in `stub_detector.py` is uncalibrated.** Benign
   flows score max ~0.278, so the baseline may never fire. Unresolved.

## Module map (`detection/`)

| File | Module | What it is |
| --- | --- | --- |
| `stub_detector.py` | M5a | per-flow scoring entry point. **Checkpoint-1 depends on it — don't break it.** |
| `autoencoder.py` | M5a | trains the baseline AE → `autoencoder_v2-256.pt` |
| `graph_builder.py` | M5b | flows → per-window host graphs; `graph_health()`, `read_flows()` |
| `gnn_model.py` | M5b | GraphSAGE graph autoencoder (the graph half) |
| `gnn_temporal.py` | M5b | the original LSTM autoencoder (the sequence half, standalone) |
| `gnn_temporal_fused.py` | M5b | **the two halves fused — this is M5b proper** |
| `ensembler.py` | M5c | fuses M5a + M5b, emits the ablation table |
| `alert_pipeline.py` | seam | `score_window()` → ScoredAlerts with both sub-scores |
| `evaluate_gnn.py` / `run_evaluation_suite.py` | eval | held-out attack-family protocol |
| `ablation.py` | eval | M5a vs M5b mechanism demo on constructed traffic |
| `drift_monitor.py` | M6 | score-distribution drift |
| `shap_explainer.py` | M7 | C's seam |

Everything has a `--help` and most have a self-test that needs no dataset
(`python detection/graph_builder.py` with no args).

## Design decisions to defend, not revisit

- **Autoencoder, never classifier.** A classifier only recognises families in
  its labels, defeating the zero-day premise, and scoring M5b as a probability
  would break the ablation (M5a scores a reconstruction distance — no shared
  threshold, no comparable ROC).
- **SAGEConv over GCNConv.** GCN's symmetric normalisation washes out the
  degree signal we're detecting.
- **Nodes = hosts, edges = directed.** One-to-many (scan) and many-to-one
  (DDoS) must not collapse into one undirected edge.
- **Time-based windows, not fixed-count.** "200 peers in 60 seconds" is a rate.
- **Edge-level alerts.** The frozen `ScoredAlert` schema needs `src_ip` and
  `dst_ip`; an edge maps onto that, a node doesn't.
- **M5a is lifted UP to host-window for comparison**, not M5b pushed down to
  flows. Ground truth is per-host; projecting a host score onto every flow
  would fabricate precision.

## Current results (as of 2026-08-11)

Mean ROC-AUC across 7 held-out CICIDS2017 families, `--limit 150000`:

| | M5a per-flow | **M5b relational** | Fused mean | Fused max |
| --- | --- | --- | --- | --- |
| mean ROC-AUC | 0.8139 | **0.9425** | 0.9397 | 0.8385 |
| range | 0.4150 – 0.9845 | 0.9059 – 0.9909 | | |

**Do not present this as a clean win.** M5a beats M5b outright on DDoS and
Botnet. The honest claim is **consistency** — M5a swings 57 points and drops
below random on WebAttacks; M5b never drops below 0.906. Fusion by max actively
hurts. `P@100` is 0.000 for every model on WebAttacks and Patator, which AUC
hides entirely.

## Conventions

- **`CHANGELOG.md` is append-only.** Newest entry at the top. Never edit or
  delete a past entry — add a correcting one. Detail lives there; commit
  messages stay short and point to it. Include results *and* caveats.
- **Commit trailer is `Assisted-by:`, not `Co-Authored-By:`.** Deep is the
  author; the agent assisted.
- **Never push `Knowledge/`.** Gitignored deliberately.
- `data/`, `venv/` are gitignored. Datasets never travel through git — each
  machine downloads its own (CIC gates them behind a registration form at
  http://cicresearch.ca/CICDataset/CIC-IDS-2017/; skip the ~50 GB PCAPs).
- Model binaries (`*.pt`) **are** tracked, so a second machine can demo without
  retraining.

## What's next

Week 3 is complete (all 8 planned steps). Outstanding:

1. **Re-run every number without `--limit 150000`** on the RTX 3090 — Monday
   alone is ~529k flows, so current results use ~28% of available data.
2. Wire the fused score into `drift_monitor.py` and D's red-team harness so the
   graph model gets attacked too.
3. Weeks 4–6 (see `Knowledge/roadmap_weeks4-6_after_pillar3_integration.md`):
   fork the AE into a **host-syscall autoencoder** for Pillar 3, run an AE-vs-HMM
   ablation, and extend the ensembler to fuse three scores.
4. `.env.example` is untracked and configures a Flask vulnerability scanner that
   doesn't exist in this repo — stray file, probably delete.

## Setup on a new machine

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python detection/graph_builder.py     # self-test, needs no dataset
```

Then copy `data/GeneratedLabelledFlows/` across or re-download it.
