# Changelog

Append-only log of what changed and why. **Pull, then read the top of this file.**

Rules:
- Newest entry goes at the **top**, directly under this header.
- **Never edit or delete a past entry.** If something was wrong, add a new entry
  correcting it. The log is the record, including the mistakes.
- Commit messages stay short and point here. Detail lives in this file.
- One entry per commit. Include results and caveats, not just a file list.

Template:

```
## YYYY-MM-DD — <short title>
**Author:** <name> (<role>) · assisted by <tool, if any>
**Commit:** <hash>

### What changed
### Why
### Results
### Caveats / notes for the team
```

---

## 2026-08-11 — Week 3: graph construction + GNN autoencoder (M5b) + ablation
**Author:** Deep (Person B — Detection Modeling) · assisted by Claude
**Commit:** _(see git log)_

### What changed

New files, all in `detection/`:

| File | Purpose |
| --- | --- |
| `graph_builder.py` | flows → per-window host-communication graphs (PyG `Data`) |
| `gnn_model.py` | GraphSAGE encoder + MLP decoder graph autoencoder (M5b) |
| `ablation.py` | controlled M5a vs M5b comparison |
| `evaluate_gnn.py` | held-out attack-family evaluation on real CICIDS2017 |
| `gnn_autoencoder_v1.pt` | trained model weights |

`graph_builder.py` also gained `read_flows()`, because the CICIDS2017
TrafficLabelling CSVs are latin-1, not UTF-8, and pandas fails on them.

### Why

This completes the **graph/relational half of M5b**, which had never been
built. `gnn_temporal.py` only ever implemented the *sequence* half — an LSTM
autoencoder — and the reference PDF §11 says so explicitly.

Worse, its per-host grouping **silently never ran**. The line
`src_ip = df['Source IP'].values if 'Source IP' in df.columns else None`
was always `None`, because the MachineLearningCVE CSVs have **no IP columns at
all** (79 columns; only `Destination Port` and `Label` identify anything). It
fell through to chunking flows in raw file order. The PDF's claim of
"per-host flow histories grouped by source IP" did not describe the code.

Design decisions worth defending in the viva:

- **Nodes are hosts**, edges are directed aggregated `(src, dst)` pairs.
  Direction matters: "one host talks to many" (scan) and "many talk to one"
  (DDoS) are different phenomena and must not collapse into one undirected edge.
- **Windows are time-based**, not fixed-count. "N peers in 60 seconds" is a
  rate; chunking by row count makes the same scan look different depending on
  how busy the network was.
- **Autoencoder, not classifier.** A classifier only recognises attack families
  present in its labels, which defeats the zero-day premise. It would also make
  the ablation meaningless — M5a scores by reconstruction distance, so scoring
  M5b by class probability gives no shared threshold and no comparable ROC.
- **SAGEConv over GCNConv.** GCN's symmetric normalisation washes out exactly
  the degree signal we are trying to detect.
- **Edge-level alerting.** The frozen `ScoredAlert` schema requires `src_ip` and
  `dst_ip`, so an edge maps onto an alert cleanly; a node does not.

### Results

Held-out attack-family protocol (PDF §17): train on Monday (100% benign), test
on a family the model has never seen. Real CICIDS2017 GeneratedLabelledFlows:

| Attack family | ROC-AUC | precision@100 | best malicious rank |
| --- | --- | --- | --- |
| PortScan | 0.8854 | 0.040 | 1 of 14,595 host-windows |
| DDoS | 0.9522 | 0.310 | 1 of 4,741 host-windows |

Controlled ablation (`ablation.py`), where the scan is built from **real benign
flows with feature values untouched** — only `src_ip`/`dst_ip` re-attributed, so
M5a must score them benign:

```
M5a (per-flow)   MISSED     flags scan at 2.5% vs 1.0% benign floor (+1.5pp = noise)
M5b (relational) DETECTED   attacker ranked 1/710, 532x above median
```

The verdict compares against the **false-positive floor, not zero**. At a 99th
percentile threshold ~1% of benign traffic flags by construction, so counting
that as detection would be counting the model's own noise.

### Caveats / notes for the team

- **Do not overclaim "graph topology caught the port scan."** CICIDS2017
  PortScan is *vertical* (one attacker → one victim, 1000 ports), so
  `out_degree` is 1 and **does not fire** (0.72× separation). What separates the
  classes is `unique_dst_ports` (199×) and `out_flows` (585×) — per-host
  *aggregation*, not message passing between hosts. The defensible claim is
  **"per-flow features destroyed the evidence; per-host structure recovered
  it."** DDoS is the family that genuinely exercises topology, and `out_degree`
  does fire there (2.60×).
- **Blocked on A for data.** None of the three datasets we had could form a
  graph. `graph_health()` now detects this before a wasted training run:
  - `MachineLearningCVE` — no IP columns at all.
  - `training_data/dataset_10k_normal.csv` — 508 clients all touching the
    identical 2 services (`8.8.8.8:53`, `10.0.0.5:80`), min = max = 2 peers.
    Every neighbourhood is the same, so all embeddings collapse to the same
    vector and the GNN learns nothing.
  - `training_data/live_capture.csv` — `dst_port` is an incrementing counter,
    giving 12,503 unique services across 12,504 flows.

  This is a **capture dependency, not a modelling bug.** Week 3 results required
  downloading CICIDS2017 **GeneratedLabelledFlows** (85 columns, has IPs).
- **Still outstanding for M5b:** the graph half and the LSTM sequence half are
  not yet fused. `gnn_model.py` scores single windows; wiring per-window
  embeddings into the existing LSTM is what makes it truly *graph-temporal*.
- **M5c (ensembler) does not exist yet.** Per PDF §6 it is B's module and the
  deliverable is a comparison table, not just "we built a GNN".
- **`DEFAULT_THRESHOLD = 0.5` in `stub_detector.py` looks uncalibrated.** Benign
  flows score max 0.278, so the baseline detector may never fire in production.
  Needs checking.

---

## 2026-08-11 — Step 0: make the project runnable on any machine
**Author:** Deep (Person B — Detection Modeling) · assisted by Claude
**Commit:** `6b050d8`

### What changed

- `venv/pyvenv.cfg` repointed at the local Python 3.12.
- Absolute `D:\Test OD\Zero-Day\...` data paths replaced with repo-root-relative
  `Path(__file__)` resolution in `autoencoder.py`, `gnn_temporal.py`,
  `drift_monitor.py`, `pipeline_test.py`.
- `gnn_temporal.py` no longer raises `RuntimeError` when CUDA is absent; it warns
  and falls back to CPU.
- Model/plot outputs no longer use cwd-relative `"detection/..."` paths.
- Added `requirements.txt`, pinned to known-good versions.
- Added README setup instructions (venv rebuild, dataset downloads).
- `.gitignore` now excludes `Knowledge/` (local-only reference material).

### Why

The repo was hardcoded to the machine it was written on and **could not run at
all** on a second machine. `pyvenv.cfg` pointed at
`C:\Users\trex2\...\Python312` — a different user profile — so no script could
even start.

A venv is **never portable**: it embeds absolute paths. Each machine must build
its own from `requirements.txt`. That is why the fix is a pinned requirements
file plus repo-relative paths, not a committed venv.

### Caveats / notes for the team

- `shap` was imported by `shap_explainer.py` but **was not installed**, so
  `stub_detector._try_shap_explanation()` was silently falling back to
  `"unknown"` for every alert. Now in `requirements.txt`.
- `.env.example` in the working tree configures a Flask "Vulnerability Scanner"
  with `app.py` and a SQLite DB. There is no Flask anywhere in this repo — it
  appears to have drifted in from another project. Left untracked pending a
  decision.
- Datasets are gitignored and never travel through git. Both machines must
  download them locally; see README.
