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

8. **Window size is a metric trade, not an upgrade.** 60s -> 1800s raises mean
   ROC-AUC 0.9173 -> 0.9832 and drops P@100 0.244 -> 0.093. **60s maximises
   P@100 and is the right default** unless the project decides AUC is the metric
   that matters. Measured over 294 runs.

9. **Architecture does not matter here.** latent 2->12 moves the mean 0.003;
   hidden 32->64 moves it 0.0002. The `latent = in_dim = 8` "no bottleneck"
   worry did not show up in the numbers. Do not spend time tuning width.

10. **More training data made it worse.** `--train-mode lodo` (2,209 graphs vs
    Monday's 487) dropped the mean 0.9300 -> 0.8405, every family down. An
    attack day's "benign" half is not clean normality.

11. **Always pass `--seed`. Nothing was seeded until 2026-08-11.** Two identical
   full-file sweeps of the same code gave mean ROC-AUC 0.8997 and 0.9251, and
   PortScan moved 6.5 points (0.8639 → 0.9291) on weight initialisation alone.
   **Any difference smaller than ~6 points between two configurations is noise
   until it is shown over multiple seeds.** Use `capacity_sweep.py`, which
   reports mean ± std, before believing any comparison.

12. **The Thursday WebAttacks CSV is 63% junk rows.** 458,968 rows, only 170,366
   labelled; the rest have NaN IPs. One NaN host makes
   `sorted(set(src) | set(dst))` raise `TypeError: '<' not supported between
   'float' and 'str'`, which killed that whole family mid-sweep and left **no
   number behind to notice was missing** — a "mean across 7 families" was
   silently a mean across 6. `graph_builder.drop_unusable_rows()` handles it now
   and prints what it drops.

13. **CSE-CIC-IDS2018 repeats gotcha #3 and adds a third naming convention.**
    9 of its 10 processed CSVs have **no IP columns**; only
    `Thuesday-20-02-2018` (typo is official) can build a graph. It also names
    columns `Tot Fwd Pkts` / `TotLen Fwd Pkts`, matching neither convention
    above — unfixed, `bytes_sent` is silently zero everywhere. Run
    `capture/schema_mapper.py` on any new dataset before training.

14. **log1p before scaling is ON by default and it is the single biggest win.**
    Plain min-max on power-law counts maps the busiest host to 1.0 and squashes
    every other host near 0, so a few huge servers permanently own the top of
    the alert queue. `NodeScaler(log=True)` (the default since 2026-08-12) fixes
    it: mean P@100 0.250 -> 0.413 at 60s, with **Patator 0.000 -> 0.618 and
    WebAttacks 0.000 -> 0.381** — the two families stuck at zero across 294
    earlier runs. Pass `--no-log-scale` (or `train(..., log_scale=False)`) only
    to reproduce a pre-2026-08-12 number. Checkpoints saved before that date
    carry no `log` key and are loaded as `log=False`, so they still score
    correctly.

    *(This supersedes an earlier note claiming those two families were outside
    what a host-graph detector can observe. The attacker really does have
    out_degree = 1, but the reason it never surfaced was the SCALING, not the
    features.)*

15. **`GraphAutoencoder` has no bottleneck.** A host has 8 features and the
    default `latent=8`, so the encoder is wide enough to pass its input through
    unchanged — and an autoencoder that can learn the identity map reconstructs
    attacks as well as normal traffic. Message passing means it is not literally
    an identity map, so this is a weakness, not a fatal flaw. **Raising `latent`
    makes it worse, not better.** If you want more capacity, add node features
    (`feature_set="v2"`), not width.

16. **We report node metrics but emit edge alerts, and the gap is 22 points.**
    Node-level mean AUC 0.8965 vs edge-level 0.6740. Every published figure
    describes the model, not the alert queue. `alert_pipeline` defaults to
    `edge_score="src"` (best of four rules, +0.023 AUC over the old `mean`).
    Quote node numbers for modelling claims and edge numbers for operational
    ones.

17. **`fused_rank_max` is the only fusion that beats both detectors** (+0.0398
    AUC over M5b alone), because it compares score POSITIONS rather than values.
    It costs P@100 (0.277 -> 0.193) and needs a population to rank against, so
    it is batch-only — `alert_pipeline` cannot use it for a single alert.

18. **`gnn_autoencoder_v1.pt` is now a 5-member ENSEMBLE checkpoint.** Its scores
    are percentiles, not raw reconstruction errors, so any threshold tuned
    against the old single-model checkpoint is meaningless. Loading handles both
    formats; `model_source` records which was used.

19. **Edge features are now scored, and it is the biggest operational win.**
    `edge_attr` was computed and discarded for the whole project. Ranking the
    source-host score together with the edge's own reconstruction error
    (`edge_score="rank_mean"`, the default) lifts edge-level AUC 0.7124 ->
    0.7892 AND P@100 0.207 -> 0.349 — the only change measured that improves
    both at once. Edge features ALONE (0.7359) beat the node-derived score.

20. **M5a saturates in production and contributes nothing useful.** Calibrated
    against Monday's benign traffic, its percentile is 0.999-1.000 on 100% of
    alerts on every attack day — an attack day differs from Monday broadly
    enough that the per-flow detector calls everything unusual. `fusion="mean"`
    is the default so M5b's ranking survives; `max` lets the saturated score
    overwrite it. Omitting `feature_columns` gives M5b only, which is the
    highest-AUC configuration measured (0.8322 edge-level).

21. **`alert_pipeline` fused uncalibrated scores until 2026-08-12.** Raw M5a
    error (0.038-0.122) versus a rank (0-1) meant `max` picked the relational
    score on 99.9% of alerts. Every alert this project emitted before that date
    was M5b alone, whatever `model_source` said. The checkpoint now carries an
    `m5a_calibrator`.

22. **Do not fuse M5a uniformly — run M5b alone unless you have a reason.**
    M5a swings 0.4763 (WebAttacks, worse than random) to 0.9895 across families.
    Its calibration bug used to saturate it into a no-op, which accidentally
    protected the fusion; with `m5a_calibration="rolling"` it is un-saturated
    and WebAttacks collapses to 0.1714 edge-level while DDoS P@100 rises
    0.760 -> 0.920. Omitting `feature_columns` gives M5b alone (0.8322 AUC), the
    most consistent configuration measured.

23. **Never unpack node feature vectors positionally.**
    `a, b, c, d, e, f, g, h = node.tolist()` breaks the moment `feature_set="v2"`
    is used (19 features, not 8). Index by position instead; indices 0–7 are
    guaranteed stable across feature sets.

24. **Results are device-sensitive — record the device on every number.**
    The same seed gave WebAttacks 0.5048 on a CPU retrain and 0.9948 on GPU
    (2026-08-21): cuBLAS/cuDNN reduction order changes training trajectories,
    and knife-edge families flip. `torch.manual_seed` alone does NOT pin CUDA.
    Every eval script must call the `set_seed()` helper (adds
    `cuda.manual_seed_all`, `cudnn.deterministic=True`, `benchmark=False`,
    `CUBLAS_WORKSPACE_CONFIG=:4096:8`) and every published number must state
    device + torch build. Never mix devices inside one comparison table.

25. **Feature set v2 was lost once — treat uncommitted work as nonexistent.**
    CLAUDE.md previously claimed v2 was "built, self-tested" but no trace
    survived in git, stashes, or the working tree; it was rebuilt from scratch
    on 2026-08-21. Lesson: if it isn't committed, it doesn't exist. Commit
    (even to a branch) before ending a session that produced code.

## Module map (`detection/`)

| File | Module | What it is |
| --- | --- | --- |
| `stub_detector.py` | M5a-L | **deprecated shim** → real code in `legacy/`. Checkpoint-1/dashboard import path kept alive; never extend |
| `autoencoder.py` | M5a-L | *(moved to `legacy/`)* trained the stale baseline AE |
| `train_m5a_revived.py` / `exp_m5a_revival.py` | M5a-R | revived per-flow AE with 11 ctx dims (87-dim) → `m5a_revived_ctx.pt`. **Not in production defaults — decision pending (see 2026-08-25c/d)** |
| `graph_builder.py` | M5b | flows → per-window host graphs; `graph_health()`, `read_flows()`; v1 (8) + v2 (19) feature sets |
| `gnn_model.py` | M5b | GraphSAGE graph autoencoder; `NodeScaler(log=True)` default, `set_seed()`, `--feature-set v1/v2` |
| `gnn_temporal_fused.py` | M5b | GNN+LSTM fused (PDF's M5b proper); measured negative vs graph-only at edge level (RC-20), kept for ablation |
| `ensembler.py` | M5c | fuses M5a + M5b, emits the ablation table; 80/20 Monday calibration holdout |
| `alert_pipeline.py` | seam | `score_window(feature_columns=None, threshold=None)` → **RC-26 M5b-only by default**; v2 requests refuse loudly without a 19-dim checkpoint |
| `drift_monitor.py` | M6 | score drift; `DetectorDriftMonitors` watches all three streams; wired via `alert_pipeline.init_drift_monitors()` |
| `evaluate_gnn.py` / `run_evaluation_suite.py` | eval | held-out attack-family protocol |
| `eval_mw_ablation_4seed.py` | eval | **reference implementation** — 6-config fusion ablation, 4-seeded, CUDA-deterministic (RC-26) |
| `eval_feature_set_v2.py` | eval | feature set v1 vs v2 + latent capacity control (RC-30) |
| `eval_external_ids2018.py` / `eval_external_ctu13.py` | eval | external replication on IDS2018 / CTU-13 (RC-29/32) |
| `eval_baselines_4seed.py` | eval | PCA/IF/MLP-AE baselines on identical features (RC-31) |
| `diag_p100.py` / `diag_p100b.py` | eval | P@100 structural-cap diagnostics (RC-27/28) |
| `ablation.py` | eval | M5a vs M5b mechanism demo on constructed traffic |
| `capture/schema_mapper.py` | data | content-based column identification |
| `capture/pcap_to_flows.py` | data | pcap → flows without CICFlowMeter |
| `experiments/` + `exp_*.py` in detection/ | evidence | sweeps behind the CHANGELOG numbers; nothing in the prod path imports them |
| `shap_explainer.py` | M7 | C's seam |
| `harness/graph_techniques.py` | D's seam | 4 evasion attacks aimed at M5b's structure |
| `harness/run_graph_harness.py` | D's seam | runs them; measures what evasion **costs** the attacker |

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

## Current results (as of 2026-08-25, week-4 freeze) — GPU, CUDA-deterministic, 4 seeds

**Headline (production recipe): GNN-logscale 60s+300s + revived 87-dim ctx M5a,
within-window rank noisyor → mean ROC-AUC 0.9996 ± 0.0001** across 7 held-out
families (`eval_mw_ablation_4seed.py --seeds 0 1 2 3`, beats pure rank_mean
0.9990 ± 0.0003 in all seeds). With v2 features (19): **0.9997 ± 0.0001**
(`eval_feature_set_v2.py`). Served live in `alert_pipeline.score_window()`.

| Family | v2 fused AUC | Attacker ranks |
| --- | --- | --- |
| PortScan / DoS / DDoS | 0.9999–1.0000 | 1–4 |
| WebAttacks / Patator | 1.0000 | 1–5 |
| Infiltration | 0.9997 | 2 |
| Botnet | 0.9987 | 5–34 |

**Operational claim (quote this, not P@100):** every attacker ranks in the top
~35 of thousands on CICIDS2017; **top-11 of 32,935 on IDS2018 in 3 of 4 seeds**
(top-35 worst; best-rank percentile 0.0002 ± 0.0003); infected host **#1-ranked
on CTU-13 Virut in all 4 seeds**, Rbot C&C #1 in 3/4 seeds, Neris worst seed
112/522k (top 0.02%). recall@100 = 1.0 on both CIC datasets. Host-level P@100 is
structurally capped at bad/100 — do not use it as a headline metric (RC-27).

**Baselines beaten under identical conditions** (RC-31, exact-matched 2026-08-25):
PCA 0.9417 · Isolation Forest 0.9357 · plain MLP-AE 0.9517 vs ours 0.9996 — same
features, same units, +4.8 pts over the best, concentrated in topology families.

**Closed negatives (do not revisit):** plain shipped M5a hurts everywhere
(0.9499±0.0021 in MW fusion — the REVIVED ctx variant is a different model and
is production); temporal/LSTM half alone adds nothing at edge level (RC-20);
LODO 5× training data hurts (gotcha #10); k=5 sim edges hurt on production
architecture; small-window filtering changes nothing (queue noise is drift, RC-28).

**Known weaknesses:** noisyor is batch-only (gotcha #17 — needs window population);
both checkpoints must ship together (`gnn_autoencoder_v1_logscale.pt` +
`m5a_revived_ctx.pt`, missing one falls back with RuntimeWarning); calibration
optimism (20% Monday holdout, still quote it); device-sensitive arithmetic
(gotcha #24) — every number above is GPU + determinism flags.

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

Weeks 3–4 experiments are **closed** (see `experiments/report_cards.md`
RC-26…RC-32). Resolved from the old list: ensembler re-run (RC-15/21),
multi-seed everything (every headline has a band), feature set v2 evaluated
(RC-30), lodo run (confirmed negative, RC-22), harness executed (RC-14).

Outstanding:

1. **v2 default flip** — `gnn_autoencoder_v1_logscale_v2.pt` shipped; flip
   `feature_set="v2"` default after team sign-off (dimension guard already in).
2. **Weeks 4–12 roadmap** (`Knowledge/`): Pillar 3 host-syscall autoencoder via
   eBPF, AE-vs-HMM ablation, three-way score fusion. Team work — B supports.
3. **Paper packaging** when results freeze: name method + protocol, one-command
   public artifact, protocol paper outline (see docs/PROJECT_GUIDE.md §6).

## Setup on a new machine

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python detection/graph_builder.py     # self-test, needs no dataset
```

Then copy `data/GeneratedLabelledFlows/` across or re-download it.
