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

## 2026-08-11 — CLAUDE.md so a second machine's agent starts with context
**Author:** Deep (Person B — Detection Modeling) · assisted by Claude
**Commit:** _(see git log)_

### What changed

Added `CLAUDE.md` at the repo root. Claude Code loads it automatically, so an
agent session on the PC starts knowing the project instead of rediscovering it.

### Why

Everything expensive learned today was invisible from the code alone: which of
the two CICIDS2017 releases can form a graph, that `Destination Port` is a
feature rather than metadata, that per-file `dropna` silently misaligns
features, that A's synthetic datasets collapse, that a venv can't be copied
between machines. A fresh agent would burn hours rediscovering each one — and
some fail *silently*, producing plausible numbers that mean nothing.

Contents: role split and what B owns, the seven hard-won gotchas, the module
map, design decisions to defend rather than revisit, current results with the
"not a clean win" framing, repo conventions (append-only changelog,
`Assisted-by:` trailer, never push `Knowledge/`), and what's next.

---

## 2026-08-11 — M5c ensembler, alert pipeline, and the ablation result
**Author:** Deep (Person B — Detection Modeling) · assisted by Claude
**Commit:** _(see git log)_

### What changed

`ensembler.py` (M5c), `alert_pipeline.py` (integration seam),
`ablation_table.md` / `.json`, and `docs/week3-presentation.html`.

### The result — read this one carefully, it is not a clean win

Mean ROC-AUC across 7 held-out families:

| | M5a per-flow | **M5b relational** | Fused mean | Fused max |
| --- | --- | --- | --- | --- |
| mean ROC-AUC | 0.8139 | **0.9425** | 0.9397 | 0.8385 |
| range | **0.4150 – 0.9845** | **0.9059 – 0.9909** | | |

Per family:

| Family | M5a | M5b | Fused mean | Fused max | Winner |
| --- | --- | --- | --- | --- | --- |
| PortScan | 0.5489 | 0.9350 | 0.9355 | 0.6709 | fused mean |
| DDoS | 0.9845 | 0.9718 | 0.9755 | 0.9845 | **M5a** |
| Botnet | 0.9625 | 0.9128 | 0.9241 | 0.9607 | **M5a** |
| Infiltration | 0.9772 | 0.9059 | 0.9148 | 0.9777 | fused max |
| WebAttacks | 0.4150 | 0.9291 | 0.9357 | 0.4148 | fused mean |
| Patator (FTP/SSH) | 0.8460 | 0.9909 | 0.9331 | 0.8888 | **M5b** |
| DoS / Heartbleed | 0.9634 | 0.9523 | 0.9590 | 0.9719 | fused max |

Three findings, all worth more than "the complex model won":

1. **M5a beats M5b outright on DDoS and Botnet.** Where attack volume is visible
   inside a single flow, the simple baseline is better. Do not claim otherwise —
   PDF §20 pre-authorised exactly this outcome.
2. **M5a is volatile; M5b is consistent.** M5a swings 57 points (0.4150 on
   WebAttacks — *worse than random* — to 0.9845 on DDoS). M5b never drops below
   0.9059. The defensible claim is **robustness across unseen families**, not
   peak performance.
3. **Fusion by max actively hurts (0.8385, worse than M5b alone).** Taking the
   max propagates M5a's false positives wholesale. Fusion by mean (0.9397) is
   fine but does not beat M5b alone either. A negative result, reported.

### Caveats / notes for the team

- **P@100 is 0.000 for every model on WebAttacks and Patator.** Nothing we have
  works operationally on those two families. AUC hides this completely.
- Two real bugs fixed in `ensembler.py` while building it:
  - `dst_port` was being dropped as metadata, but in the CICIDS2017 releases
    "Destination Port" **is** one of the 76 model features. Verified the 76
    columns are identical and in the same order across both releases.
  - Feature columns are now **pinned once from the training file** and reused.
    Deriving them per-file with `dropna(axis=1)` would silently drop different
    columns on different attack days and feed the model misaligned features —
    the scores would have looked plausible and meant nothing.
- `alert_pipeline.py` is a **new** module rather than an edit to
  `stub_detector.py`, which Checkpoint-1 depends on. `score_flow()` also has the
  wrong shape for a graph detector: a graph score is undefined for one flow in
  isolation. `score_window()` is the correct seam. Sub-scores are additive, so
  nothing downstream breaks.
- All numbers still use `--limit 150000` rows per file. Full-file runs pending.

---

## 2026-08-11 — M5b complete: graph+temporal fusion, and the full family sweep
**Author:** Deep (Person B — Detection Modeling) · assisted by Claude
**Commit:** _(see git log)_

### What changed

| File | Purpose |
| --- | --- |
| `gnn_temporal_fused.py` | **the fused graph-temporal model — this is M5b proper** |
| `run_evaluation_suite.py` | trains once, sweeps every attack family |
| `evaluation_results.md` / `.json` | the results table |

### Why

The PDF defines M5b as *"graph structure **+ sequence**"*. The project had both
halves and they did not talk: `gnn_temporal.py` was the LSTM sequence half,
`gnn_model.py` the graph half. Two disconnected models is not a graph-temporal
model. This fuses them, trained jointly end-to-end:

1. Window traffic → one host-communication graph per window
2. GNN encodes each window → structure-aware embedding per host
3. Per host, the embeddings across T=5 windows form a sequence
4. An LSTM autoencoder reconstructs that host's original **feature** sequence

Reconstructing features rather than embeddings is deliberate: it keeps error in
the same interpretable units as M5a and the graph-only model (so the ablation
stays controlled), and stops the model trivially learning an identity map on its
own embeddings.

**What fusion buys:** a single window cannot tell "a backup server that always
fans out to 200 machines at 02:00" from "a laptop that never has and just
started". Both are the same graph. Only the sequence separates a stable pattern
from a change — the slow, gradual attacker the red-team harness simulates, and
precisely where the graph-only model is weakest.

### Results

Held-out family sweep, trained once on Monday (benign only), 182 graphs:

| Attack family | ROC-AUC | P@100 | R@100 | Best rank | Top feature | Sep |
| --- | --- | --- | --- | --- | --- | --- |
| Patator (FTP/SSH) | 0.9913 | 0.000 | 0.000 | 185 of 34,066 | `out_flows` | 30x |
| DoS / Heartbleed | 0.9536 | 0.280 | 0.431 | 2 of 17,022 | `out_flows` | 321x |
| WebAttacks | 0.9515 | 0.000 | 0.000 | 433 of 26,443 | `bytes_sent` | 18x |
| DDoS | 0.9436 | 0.320 | 0.552 | 1 of 4,741 | `bytes_sent` | 557x |
| Botnet | 0.9287 | 0.440 | 0.041 | 8 of 24,281 | `bytes_sent` | 73x |
| Infiltration | 0.9282 | 0.200 | 0.161 | 4 of 19,718 | `unique_dst_ports` | 72x |
| PortScan | 0.9081 | 0.040 | 0.235 | 1 of 14,595 | `out_flows` | 585x |

**Mean ROC-AUC across 7 unseen families: 0.9436.**

### Caveats / notes for the team

- **High AUC does not mean good alerts. Say this before an examiner does.**
  Patator scores AUC 0.9913 but **P@100 = 0.000** — not one true positive in the
  top 100 alerts, because 184 benign host-windows outrank the first attacker.
  WebAttacks is the same (0.9515 AUC, 0.000 P@100). AUC measures average
  ranking across the whole set; a SOC analyst only ever sees the top of the
  queue. **P@100 is the honest operational metric here, and on two of seven
  families it is zero.** This is a real weakness, not a presentation detail.
- The fused model needs a host to appear in **≥5 consecutive windows**. A
  single-burst attacker produces no sequence and is invisible to it — the
  graph-only model catches those. The two are genuinely complementary, which is
  the strongest available argument for building M5c rather than picking one.
- Synthetic scan traffic in `graph_builder._synthetic_flows()` now spans many
  minutes rather than one timestamp. Previously the whole scan sat in a single
  window, so the fused self-test filtered the attacker out and passed
  vacuously.
- Numbers above use `--limit 150000` rows per file. Full-file runs are pending
  a machine with more headroom (RTX 3090).

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
