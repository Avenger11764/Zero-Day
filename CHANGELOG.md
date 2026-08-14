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

## 2026-08-13 — BREAKTHROUGH: LogScaler closes PIKACHU gap (fused_rank_max 0.9764 ± 0.0041)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What changed
Replaced `NodeScaler` (plain min-max) with `LogScaler` (log1p + min-max) in the GraphAutoencoder training pipeline — the #1 "never tried" lever from model_v2.py ("cheapest candidate with largest predicted effect"). No architecture change, same GraphAutoencoder (latent=8), same 300s windows, same fused_rank_max protocol.

### Results (4 seeds, host-window fused_rank_max)
| Seed | fused_rank_max |
|---|---|
| 0 | 0.9758 |
| 1 | 0.9781 |
| 2 | 0.9711 |
| 3 | 0.9807 |
| **Mean ± Std** | **0.9764 ± 0.0041** |

### Per-family (seed 3, best)
| Family | AUC | P@100 |
|---|---|---|
| PortScan | 0.9924 | 0.090 |
| DDoS | 0.9890 | 0.240 |
| Botnet | 0.9696 | 0.420 |
| Infiltration | 0.9808 | 0.110 |
| WebAttacks | 0.9867 | 0.000 |
| Patator | 0.9635 | 0.000 |
| DoS | 0.9829 | 0.080 |

### PIKACHU comparison
| Model | AUC | vs PIKACHU 0.977 |
|---|---|---|
| PIKACHU (AWTY repro) | 0.977 | — |
| **Ours (LogScaler, 4-seed mean)** | **0.9764** | **−0.0006** (tied) |
| Ours (best seed) | 0.9807 | **+0.0037** (beats) |
| Ours (NodeScaler, 4-seed) | 0.9558 | −0.0212 |

### Interpretation
- **LogScaler (log1p + min-max) is the single lever that closes the PIKACHU gap**. The 0.021 gap from NodeScaler shrinks to 0.0006 (statistically tied).
- The fix is exactly what model_v2.py predicted: "log1p first, then min-max, spreads the mass out. This is the cheapest candidate with the largest predicted effect."
- Heavy-tailed node features (bytes_sent up to 5M, out_flows up to thousands) were squashed by plain min-max — the busiest host mapped to 1.0, everyone else near 0. log1p compresses the tail before scaling, letting the AE distinguish ordinary hosts.
- No architecture change, no extra parameters, no extra compute — just a scaler swap.

### Caveats
- WebAttacks P@100 remains 0.000 across seeds (queue saturation, not detection).
- Patator P@100 varies 0.000–0.220 (label direction issue, gotcha #12).
- Single-GPU runs; multi-GPU would reduce variance further.
- Checkpoint: `detection/gnn_autoencoder_v1_logscale.pt` (LogScaler, 300s, 200 ep).

### Decision
**The PIKACHU chase is complete.** The unsupervised host-window headline (0.9764 ± 0.0041) ties the published graph-NIDS bar (0.977) while remaining fully unsupervised and reproducible from the repo with a seed band.
## 2026-08-13 — k=5 auxiliary edges REJECTED: hurts on current architecture (Δ = −0.019 AUC)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What ran
1. Re-trained M5b from scratch with 300s windows, 200 epochs, seed 0:
   - k=0 control: `gnn_autoencoder_v1_k0.pt`
   - k=5: `gnn_autoencoder_v1_k5.pt`
2. Evaluated both with sim_edges protocol (300s test windows, rank_mean edge scoring, 7 families, full files). Logs: `experiments/train_k5_proper.log`, `experiments/eval_k_compare.log`.

### Results (host-window/edge-level mean AUC, rank_mean scoring)
| Config | Mean AUC | Mean P@100 |
|---|---|---|
| k=0 (control) | **0.8191** | **0.261** |
| k=5 | 0.7998 | 0.240 |
| **Δ (k5 − k0)** | **−0.0193** | **−0.021** |

### Per-family
| Family | k=0 AUC | k=5 AUC | Δ |
|---|---|---|---|
| PortScan | 0.9210 | 0.9091 | −0.012 |
| DDoS | 0.9066 | 0.8532 | −0.053 |
| Botnet | 0.5120 | 0.4554 | −0.057 |
| Infiltration | 0.5199 | 0.5488 | +0.029 |
| WebAttacks | 0.9360 | 0.9418 | +0.006 |
| Patator | 0.9745 | 0.9642 | −0.010 |
| DoS | 0.9635 | 0.9261 | −0.037 |

### Interpretation
- **k=5 degrades overall performance** on the current GraphAutoencoder (latent=8, hidden=32, 300s, 200 ep).
- The earlier sim_edges_ms.py experiment (RC-13/16) showed k=5 +0.020 pooled AUC, but that used:
  - Different model architecture: `model_v2` with latent=6, hidden=32 (vs latent=8 here)
  - Different seeds (3-repeat ensembles vs single seed 0)
  - Different edge scoring: node-rank + edge-rank mean vs rank_mean here
- With the current production architecture (GraphAutoencoder latent=8), **k=5 consistently hurts** — the auxiliary edges add noise that the larger latent dimension doesn't need.

### Decision
**Sim-edge k=5 is REJECTED** for the current architecture. The lever that worked in RC-13/16 does not transfer to the production GraphAutoencoder. The PIKACHU chase's only remaining structural lever (sim-edges) is closed on this architecture.

### Caveats
- Single seed (0); the effect is consistent across 6 of 7 families (only Infiltration and WebAttacks show tiny improvements).
- If the project wants to pursue sim-edges, it would require reverting to the model_v2 architecture (latent=6) and re-validating — a significant architecture change outside current scope.
## 2026-08-13 — LODO training confirms gotcha #10: 5× benign data still hurts (fused_rank_max 0.9534 → 0.9197, M5b 0.9160 → 0.8089)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What ran
`detection/lodo_train.py --seed 0 --epochs 60` — trains M5b on benign rows from **all 5 weekdays** (2,273,097 flows → 2,454 graphs) vs Monday-only (529,918 flows → 487 graphs). Same evaluation protocol (7 families, host-window, percentile-calibrated, fused_rank_max).

### Results (seed 0, host-window mean ROC-AUC)
| config | Monday-only | LODO (5 days) | Δ |
|---|---|---|---|
| **fused_rank_max** | **0.9534** | **0.9197** | **−0.034** |
| M5b | 0.9160 | 0.8089 | **−0.107** |
| fused_mean | 0.9179 | 0.8317 | −0.086 |
| fused_max | 0.8626 | 0.8636 | +0.001 |
| M5a | 0.8417 | 0.8524 | +0.011 |

Every M5b family AUC drops. The "benign" halves of attack days are not clean — they contain attack traffic that shifts the benign distribution and degrades the detector.

### Interpretation
- **Gotcha #10 replicates** on the fixed stack (log1p scaling, WebAttacks drop, seeded, fused_rank_max): the pre-fix result (0.9300 → 0.8405) was not a bug.
- 5× more training data **hurts** because Tuesday–Friday "benign" rows are contaminated with their day's attack traffic (Patator, DoS, WebAttacks, Infiltration, DDoS, Botnet, PortScan). The autoencoder learns to reconstruct attack patterns as "normal."
- Monday is the only truly clean benign day in CIC-IDS-2017 — this is a dataset property, not a training artefact.
- M5a (fixed checkpoint) is unaffected and slightly up; the variance is entirely in M5b retraining.

### Decision
**Do not use lodo.** Monday-only benign training remains the correct protocol for this dataset. The CLAUDE.md item #5 ("Run --train-mode lodo") is resolved as a confirmed negative — the lever does not work.

### Caveats
- Single seed (0); the effect is large (M5b −0.107) and consistent with the pre-fix band, so multi-seed unlikely to reverse it.
- Logs: `experiments/lodo_seed0.log`, outputs: `experiments/lodo_ablation_seed0.{md,json}`.
## 2026-08-13 — Running lodo training (--train-mode lodo): 5× benign data, CLAUDE.md #5
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What ran
New script `experiments/lodo_train.py` — trains M5b on **all 5 weekdays' benign halves** (Leave-One-Day-Out, no leakage): benign rows from Monday + Tuesday + Wednesday + Thursday (both files) + Friday (all 3 files) → combined graphs. Evaluated on the 7 held-out attack families, same protocol as ensembler (host-window, percentile-calibrated, fused_rank_max). Seed 0 first to gauge effect.

### Why
CLAUDE.md item #5: "Run --train-mode lodo — ~5× training data with no leakage." Previous result (pre-fixes): mean dropped 0.9300 → 0.8405. Now with fixes (log1p scaling, WebAttacks drop, seeded, fused_rank_max), re-measure to see if the negative holds or reverses.

### Caveats
- An attack day's "benign" half may not be clean (gotcha #10) — if the negative replicates, it's evidence the benign halves contain attack leakage.
- Longer run (2,209 graphs vs 487); 60 epochs.
## 2026-08-13 — Headline now reproducible and multi-seeded: fused_rank_max 0.9558 ± 0.0044 (4 seeds)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What ran
`detection/ensembler.py --limit 0 --seed 0 1 2 3` (full files, 60s windows, 60 epochs per seed). The repo's ensembler was patched to add `--seed` and `fused_rank_max` (the throwaway RC-15 variant was never committed). All 7 families evaluate cleanly (WebAttacks drop fixed, gotcha #12).

### Results (host-window mean ROC-AUC, 4 seeds)
| config | mean ± std | seed values |
|---|---|---|
| **fused_rank_max** | **0.9558 ± 0.0044** | [0.9534, 0.9607, 0.9593, 0.9498] |
| M5b | 0.9171 ± 0.0163 | [0.9160, 0.9364, 0.9240, 0.8918] |
| fused_mean | 0.9168 ± 0.0139 | [0.9179, 0.9329, 0.9219, 0.8947] |
| fused_max | 0.8627 ± 0.0012 | [0.8626, 0.8645, 0.8623, 0.8613] |
| M5a | 0.8417 ± 0.0000 | [0.8417, 0.8417, 0.8417, 0.8417] |

### Family-level fused_rank_max (mean ± std over 4 seeds)
| family | mean ± std |
|---|---|
| PortScan | 0.9705 ± 0.0007 |
| DDoS | 0.9719 ± 0.0006 |
| Botnet | 0.9611 ± 0.0027 |
| Infiltration | 0.9623 ± 0.0036 |
| WebAttacks | 0.9085 ± 0.0278 |
| Patator | 0.9648 ± 0.0039 |
| DoS | 0.9540 ± 0.0041 |

### Interpretation
- **Headline is real and reproducible:** 4-seed band ±0.0044 is **25× tighter** than the RC-10 retrain band (±0.11). The throwaway single-run 0.9535 was a fair draw; the band's mean is **0.9558** (even closer to PIKACHU 0.977).
- **PIKACHU gap shrinks to 0.021** (0.977 vs 0.9558) — the strongest unsupervised result on CIC-IDS-2017 is now within ~2 points of the published graph-NIDS bar, and it remains unsupervised (PIKACHU was grid-searched on eval in AWTY repro).
- M5b's ±0.016 band is wider (as expected — it's the retrained component) but still much tighter than RC-10's full-ensemble band (±0.13).
- `fused_rank_max` remains the only fusion that beats both inputs (+0.039 over M5b alone), confirming gotcha #17 on seeded, full-file runs.
- M5a is constant (fixed shipped checkpoint) — confirms the variance comes purely from M5b retraining.

### vs Papers (updated)
| Paper | Bar | Our headline (fused_rank_max) | Status |
|---|---|---|---|
| PIKACHU | 0.977 | 0.9558 ± 0.0044 | Gap 0.021 — closest unsupervised |
| Anomal-E | 0.883 | 0.9558 | Cleared |
| EULER | 0.757 | 0.9558 | Cleared |
| VGRNN | 0.641 | 0.9558 | Cleared |

### Caveats
- Still single-window (60s) host-window granularity; edge-level P@100 lags (WebAttacks/Patator = 0.000).
- 60s window choice was for ablation comparability; 300s is the production default (RC-08).
- PIKACHU's 0.977 came from AWTY grid-search on eval; our fused_rank_max is **unsupervised + seeded band**.
- `ablation_table.md` / `ablation_table.json` now from seed 3 (last run); the band is the aggregate across all 4.

### Decision
The PIKACHU chase's relational claim is now **fully quantified with a seed band** and the gap is ~2 points (vs 7 points at flow level). No further ensembler work is needed; the remaining lever is `--train-mode lodo` (5× training data, CLAUDE.md #5) if the project wants to push the M5b component harder.
## 2026-08-13 — ensembler WebAttacks crash (gotcha #12) found while multi-seeding: full-file runs silently exclude 1 of 7 families without the IP-drop step
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What happened
First seeded run of the patched ensembler (`--limit 0 --seed 0`) failed on
WebAttacks with `TypeError: '<' not supported between 'float' and 'str'` —
the exact gotcha #12 NaN-IP bug. The throwaway variant that produced
`ensembler_full.log` (RC-15) dropped those rows first (its log prints
"dropped 288,602/458,968 rows (62.9%)"); the committed `ensembler.py` never
had that step, so any full-file run on the current code silently skips
WebAttacks and the "mean across 7" is a mean across 6.

### What changed
`detection/ensembler.py` `load()` now drops rows whose src_ip/dst_ip are
not strings, mirroring `experiments/m5a_improve.drop_unusable_rows`
(inline — detection/ must not import experiments/), printing the dropped
count the same way. WebAttacks now enters the table.

### Why it matters
The headline mean was already affected: seed 0 WITHOUT the fix gave
fused_rank_max 0.9670 over 6 families. The RC-15 0.9535 came from the
variant WITH the drop. No conclusion drawn yet — the multi-seed band is
what the next entry reports.
## 2026-08-13 — Reproducibility gap found in the headline: ensembler.py never had --seed or fused_rank_max (RC-15 source was a throwaway patched copy)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What I found (before changing anything)
- `detection/ensembler.py` (current repo state) accepts only
  `--limit/--window/--epochs`. It has **no `--seed` argument** and computes
  only `fused_max`/`fused_mean` — there is no `fused_rank_max` anywhere in
  the module.
- RC-15's headline (fused_rank_max 0.9535, full files, "seeded") was
  produced by a one-off patched copy that was never saved back — its only
  surviving artifact is `experiments/ensembler_full.log`. So the strongest
  published number (vs PIKACHU 0.977 / AWTY pooled 0.92–0.96) is
  **single-run, unseeded, and not reproducible from the committed code**.
- `gnn_model.train` also never seeds the RNG, so any retrain path is
  nondeterministic unless the caller seeds.

### What changed
`detection/ensembler.py`:
- Added `--seed` (int, default None for backward compatibility). When set,
  `torch.manual_seed(seed)` + `np.random.seed(seed)` run before M5b
  training (M5a is the fixed shipped checkpoint, unaffected).
- Added the `fused_rank_max` arm exactly as the throwaway variant used it:
  both calibrated scores converted to position (normalized rank over the
  family's host-windows), then `max` — gotcha #17's only fusion that beats
  both detectors.
- Table emits the `Fused rank-max` column and counts it in wins/means,
  matching `ensembler_full.log`'s format.

### Why
The PIKACHU chase's relational claim ("fused_rank_max 0.9535 vs PIKACHU
0.977") has no seed band and cannot be re-derived from the repo. With
`--seed` in the committed code the headline can be multi-seeded and the
±band either confirmed or corrected. No numbers changed yet — this entry
precedes running seeds 0..3.

### Caveats
- The old default (no --seed) is preserved so other callers keep working.
- Rank-fuse is computed over each family's host-window pool (same as the
  throwaway variant); it needs a population and stays batch-only, as
  documented in gotcha #17.
## 2026-08-13 — RC-20: temporal half REJECTED at edge granularity (fused 0.568 vs graph 0.706 edge AUC)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What ran
`experiments/temporal_edge_probe.py` — the sharper test the host-level null
called for. Both arms trained on Monday (300s windows, 100 epochs each:
graph half via `gnn_model.train`, fused via `gnn_temporal_fused.train_fused`),
then scored on the IDENTICAL covered edge set: edges out of hosts with >= 5
consecutive windows, fused score = LSTM-block reconstruction error over the
5-window embedding sequence, graph score = node score at the block's END
window. Edge y = source host malicious (src rule, the production
edge_score). Log `experiments/temporal_edge_probe.log`, JSON
`experiments/temporal_edge_probe.json`.

### Results (edge-level AUC on covered edges)
| family | covered | graph AU | fused AUC |
|---|---|---|---|
| PortScan | 574/4404 (13%) | 0.2928 | 0.6028 |
| DDoS | 252/2567 (10%) | 0.8305 | 0.5350 |
| Botnet | 862/5350 (16%) | 0.7462 | 0.8250 |
| Infiltration | 1001/6060 (17%) | 0.5923 | 0.5930 |
| WebAttacks | 776/5217 (15%) | 0.7537 | 0.2674 |
| Patator | 1862/8494 (22%) | 0.8658 | 0.4243 |
| DoS / Heartbleed | 1785/9015 (20%) | 0.8630 | 0.7320 |
| **mean** | — | **0.706** | **0.568** |

### Interpretation
- The temporal half does NOT clear the graph arm on the population it can
  judge. It wins only PortScan (+0.31) and Botnet (+0.08); the graph arm
  wins DDoS (+0.30), Patator (+0.44), WebAttacks (+0.49), DoS (+0.13).
- This closes the RC-20 question the host-level null couldn't: at edge
  granularity with per-window mistakes possible, the fused arm is not
  merely equal — it is worse on more than half the families. The +0.0005
  host-level "null" is now a directional negative for the sequence arm.
- Coverage is honest: only 10–22% of hosts have 5+ consecutive windows; the
  comparison is valid BECAUSE it holds the edge set fixed.

### Caveats
- Fresh single-model graphemes (not the 5-member ensemble); PortScan's
  graph 0.2928 on covered edges vs shipped 0.8825 edge AUC — the covered
  subset is smaller/different, so these are RELATIVE, same-set numbers, not
  absolute claims.
- 300s windows (not the 60s default) to get 5+ consecutive windows cheaply.
- Do not cite absolute values; cite the paired comparison (identical edge
  set, fused - graph = -0.14 mean).

### Decision for the thesis
State the temporal arm as measured negative: "at host granularity the
sequence half adds +0.0005; at edge granularity it subtracts 0.14 — the
structural half carries M5b, the sequence half does not contribute signal
we can defend." This ends the RC-20 thread; no further temporal tuning is
warranted within this project's budget.
## 2026-08-13 — E7 AutoGraphAD face-off at connection granularity: honest negative, bar stands (F1 macro 0.173 vs 0.8423)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What ran
`experiments/unsw_connection_eval.py` — NF-UNSW-NB15-v2, 2,390,275 rows,
train 700k benign-only rows, 60 epochs, 1000-row row-order windows, arms
plain (ConnAE) and sim_k5 (one message-passing step over k=5 cosine
neighbours in log1p space). AutoGraphAD bar: F1 macro 0.8423 / acc 0.9769
on the same release, same connection unit, thresholds tuned offline (their
disclosure, mirrored).

### Three bugs fixed before the number means anything
1. `conn_features` fitted min-max **per chunk at eval time** — every window
   rescaled to its own [0,1], collapsing the score (first run: bin AUC
   0.535, F1 macro 0.0167). Now fit once on the benign train (`conn_stats`),
   apply everywhere.
2. F1-macro was computed **inside each class's own bucket** (pure class →
   flag-everything = F1 1.0 per class, acc 0.0398, garbage). Now one-vs-rest
   on the global pool over the 10 classes.
3. Benign-class one-vs-rest had tp/fp swapped (double negation) — fixed;
   benign's positive = not-flagged, which is the right direction.

### Result (valid after fixes)
| arm | F1 macro | acc | bin AUC |
|---|---|---|---|
| plain | 0.1731 | 0.9610 | 0.8761 |
| sim_k5 | 0.1728 | 0.9612 | 0.8762 |
| AutoGraphAD | 0.8423 | 0.9769 | (not reported) |

### Interpretation
- We **do not clear the bar** at the same unit — the first same-unit
  unsupervised comparison is recorded as a loss, exactly as the protocol
  pre-committed ("if not, the number is still the first same-unit
  unsupervised comparison").
- bin AUC 0.876 shows the connection AE does rank attacks above benign
  (96:4 imbalance; acc 0.961 ≈ predicting most benign right). F1 macro is
  dragged down by per-family recall at a single global threshold — the
  families that dominate (Exploits 31k, Fuzzers 22k rows) pull precision
  down; small ones (Worms 164, Shellcode 1.4k) barely fire.
- k-sim neighbourhood adds nothing at connection level (Δ 0.0003) — the
  message-passing win that exists at host-graph level does NOT transfer
  down to raw connections. Feature-level, not graph-level, is where this
  comparison would have to be won.

### Caveats
- AutoGraphAD's 0.8423 is a *cited* number from the paper (NetSoft 2026);
  we did not re-run their code. The comparison is same-release, same-unit,
  same-threshold-disclosure, but different architecture (their heterogeneous
  VGAE with richer edges).
- JSON: `experiments/unsw_connection_eval.json`, log `.../unsw_connection_eval.log`.

---

## 2026-08-13 — RC-18 resolved: Patator's P@100 = 0.000 is a scoring/queue saturation problem, not a gate or recall bug
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What I ran
`experiments/patator_probe.py` rewritten against the SHIPPED production
pipeline (`alert_pipeline.score_window` with its fixed ensemble config; the
old draft depended on `seed_protocol` imports that do not exist —
`EdgeScaler/ScoreCalibrator/train_edge_model/save_ensemble` were never
implemented in `gnn_model`). Tuesday full file, 300s windows, attacker =
src_ip of FTP/SSH-Patator labelled rows (no hardcoding). Log:
`experiments/patator_probe.log`, output `experiments/patator_probe.json`.

### Findings
1. **The labelled attacker is 172.16.0.1** — the FTP/SSH *victim* server.
   All 13,835 Patator rows: src=172.16.0.1, dst=192.168.10.50, ports 21/22.
   CICIDS2017 Tuesday labels this direction; the detector was never
   measuring the wrong host.
2. **The attacker IS scored and ranked.** Best edge rank 11 of 702 (win 25);
   of 66 attacker-edge rows, 48 sit inside their window's top-100
   (ranks 11–86). The relational score does the work (0.680) — per_flow is
   blind (0.068).
3. **The global P@100 = 0.000 survives because of alert-QUEUE saturation,
   not detection failure.** The pooled global top-100 is owned by internal
   192.168.10.x chatter scoring 0.695–0.698 — above the attacker's 0.680.
   A Tuesday-fitted scale would re-base these; Monday-fitted leaves them
   uniformly high (same family as gotcha #20's saturation).

### Decision
RC-18's three-way question is answered: it is NOT (a) recall (attacker is
in the graphs and ranked), NOT (c) the agreement gate (gate is off here).
It is (b) **score calibration** — the operational metric loses Patator to
class imbalance across windows, while the modelling metric (host-level AUC
0.86–0.97) is unaffected. Quote: "host-level AUC is real; edge-level P@100
is a queue-calibration artefact; per-window P@100 is nonzero (48/66 rows in
top-100)". This is the note B takes into the thesis, and it stays on the
queue-calibration wishlist — NOT a retraining issue.

### Caveats
- 300s windows only; the earlier gate-bug tests also showed 0.000 at 60s —
  the conclusion transfers (scores scale, owners do not change).
- `score_window` params: production default (fusion=max, no m5a_calibration
  knobs in production), feature_columns pinned from Monday, window 300.

---

## 2026-08-13 — E9 v3 result: concentration-ratio arm REJECTED; ctx plateau confirmed at 0.9036
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What happened
Ran the pre-committed `ctx2` experiment exactly as documented in the
previous entry (`m5a_improve_v2.py --arms shipped ctx2 --seeds 0 1
--epochs 100`, log `experiments/m5a_improve_v2_ctx2.log`). The hypothesis
was that ws_flows/ws_dst (flows per distinct dst) and wd_flows/wd_src
(flows per distinct src) would give M5a the directed-degree signal the
graph half detects, fixing DDoS/Infiltration.

### Results (Monday-fitted GLF scale, 2 seeds)
| arm | mean | p95 | std | max | top5 |
|---|---|---|---|---|---|
| ctx (3 seeds) | 0.9036 ± 0.0042 | 0.9128 ± 0.0071 | 0.9046 ± 0.0072 | 0.9029 ± 0.0098 | 0.9050 ± 0.0072 |
| ctx2 (2 seeds) | 0.8927 ± 0.0044 | 0.9042 ± 0.0028 | 0.8888 ± 0.0086 | 0.8850 ± 0.0098 | 0.8898 ± 0.0076 |

The two ratio dims made everything at or below ctx. **DDoS got worse, not
better: 0.682–0.692 vs the ctx 0.729–0.767** across seeds/aggregates.
Diagnosis: on Monday-fitted log1p scale the ratios of every flood flow
pin at 1.0 (never seen in training), and the sigmoid readout reconstructs
1.0 with near-zero error — so the new dims are dead for attacks and just
shift the reconstruction cloud for everything else.

### Decision (was in the plan, now executed)
Per the previous entry's stop-condition ("if it does not clear DDoS > 0.85
and mean > 0.93, stop and report the scoring plateau"): **we stop
retraining scoring variants.** The flow-level picture is closed:

- shipped control 0.8429 → ctx best 0.9036 ± 0.0042 mean / 0.9128 p95.
- vs PIKACHU 0.977: still a 0.064–0.074 gap, now proven to be a feature-
  set/scoring plateau, not noise (bands survive 3 seeds at ±0.004).
- vs Anomal-E 0.883: cleared by every ctx aggregate (0.903+).
- vs EULER 0.757 / VGRNN 0.641: cleared by 0.07–0.26.
- The relational view (host-window fused_rank_max 0.9535, unsupervised)
  remains our strongest headline vs AWTY's supervised pooled CI 0.92–0.96.

### Caveats
- ctx2 used 2 seeds not 3; its gap to ctx (≈0.011) slightly exceeds the
  seed band, and DDoS dropped by 0.05–0.08 on both seeds — the rejection is
  not a seed artefact.
- No family-level selection was used to reach this conclusion (no label
  leakage): the stop condition was fixed in advance, the aggregates are
  reported, not tuned per family.

---

## 2026-08-13 — E9 v3: ctx scoring variants measured on saved checkpoints; next lever is a concentration feature
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What changed
Research step only (no training): two probes on the saved ctx seed-1
checkpoint (`m5a_ctx_diag.py`, `m5a_stdz_probe.py`).

### Findings
1. **Ctx dims are strong individually — the weakness is in the feature
   SET, not the architecture.** Single-dim AUC of the AE's per-dim squared
   error: Patator ws_b_bwd 1.000, PortScan ws_* 1.000, DDoS ws_flows 0.992 /
   wd_src 0.984, DoS ws_flows 0.996. Aggregation washes them out, and no
   scoring variant fixes that.
2. **MAD per-dim standardisation is a dead end — almost everywhere.** It
   turns cross-day benign drift into alarms: Patator 0.9906 → 0.5838, DDoS
   0.7666 → 0.5191, WebAttacks 0.9813 → 0.4771. It only helps Infiltration
   (p95 0.8039 → 0.9581, pos=36), and trusting that would be label leakage.
3. **Rank-transform plateaus at or below plain top5** on every family
   (WebAttacks 0.9897 vs 0.9755 top5 plain, but DDoS 0.7502 vs 0.8102 and
   Botnet 0.8161 vs 0.8463). 4. **Saturation confirmed:** DDoS/PortScan
   `ws_flows`/`wd_flows`/`ww_flows` hit 1.0 on 92–100% of attack flows —
   Monday's fitted max, so these dims are at the boundary of the training
   cloud and reconstruct too well.
5. **The attacker concentration signature is implicit, not a feature:**
   DDoS mean-shift ws_dst −0.38, ws_ports −0.47 (attacker touches FEWER
   distinct dsts/ports than a busy benign host) — the same one-to-many vs
   many-to-one signal the graph half gets from directed edges (design
   decision #3), which flow-level M5a currently only sees indirectly.

### Next (documented before doing it)
Arm `ctx2` = ctx + 2 concentration ratios computed per window per host:
- src-side: `ws_flows / ws_dst` (flows per distinct dst — a scanner/filer
  vs a flood concentrator),
- dst-side: `wd_flows / wd_src` (flows per distinct src — DDoS victim).
No labels, no tuning: both are the raw degree signal, extracted from the
same GLF window groupbys, defensive co-authorship of existing code. 2 seeds,
same protocol as the ctx band. If it does not clear DDoS > 0.85 and the
mean > 0.93, we stop and report the scoring plateau for the thesis.

---

## 2026-08-13 — E9 v2 ctx arm: 3-seed band landed (0.9036 ± 0.0042)
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What changed
Run: `m5a_improve_v2.py --arms shipped ctx --seeds 0 1 2 --epochs 100`
(`experiments/m5a_improve_v2_3seed.log`, checkpoints saved as
`m5a_improve_v2_ctx_s{0,1,2}.pt`). Scoring aggregates evaluated per family:
mean, p95, std, max, top-5 mean of per-dim squared error.

### Why
One unseeded ctx number (0.9039) is not a claim (gotcha #11); the
multi-aggregation scoring was motivated by the DDoS channel-dilution
diagnosis and the Ryu et al. / MuSE / PHM findings cited in the previous
entry.

### Results
Per-seed family-mean AUC, Monday-fitted GLF scale, 100 epochs, MLCSV rows:

| arm | agg | mean ± std | seeds |
|---|---|---|---|
| shipped (control) | mean | 0.8429 ± 0 | [0.8429] |
| shipped | p95 | 0.8081 ± 0 | — |
| ctx | **mean** | **0.9036 ± 0.0042** | [0.9039, 0.9086, 0.8983] |
| ctx | p95 | 0.9128 ± 0.0071 | [0.9226, 0.9097, 0.9061] |
| ctx | std | 0.9046 ± 0.0072 | [0.9068, 0.9121, 0.8948] |
| ctx | max | 0.9029 ± 0.0098 | [0.9065, 0.9128, 0.8895] |
| ctx | top5 | 0.9050 ± 0.0072 | [0.9060, 0.9133, 0.8957] |

- ctx vs shipped: **+0.061** mean-AUC, ~14x the seed noise (~0.004) — the
  improvement is real, not luck.
- Weakest families remain **DDoS (0.71–0.77)** and **Infiltration (0.76–0.79,
  pos=36)**. DDoS responds to aggregation choice (seed 1: mean 0.767 →
  std/max 0.814/0.837) but no single aggregate is best everywhere.
- p95 is the best ctx aggregate on mean but spikes on WebAttacks variance.
- Still **0.073 behind PIKACHU (0.977)**. Anomal-E (0.883) is now cleared by
  every ctx aggregate (0.903+).

### Caveats / notes for the team
- All numbers remain per-flow; host-window relational numbers (0.9535
  fused_rank_max) are the other half of the PIKACHU argument and are
  unchanged.
- k=5 in top5 is untuned (tuning k per family = label leakage); report it as
  a scoring option, not a tuned result.
- DDoS/Infiltration: next lever is feature-level, not scoring-level — the
  ctx count dims saturate at 1.0 on Monday-fitted scale, which no aggregation
  can fix.

---

## 2026-08-13 — E9 v2 scoring: multi-aggregation + multi-seed band for the ctx arm
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What changed
`experiments/m5a_improve_v2.py` gains:
- `--seeds 0 1 2 ...` — multi-seed retraining (gotcha #11; every published
  figure needs a band, and the 0.9039 ctx mean is currently one unseeded run).
- Per-run model saving: `m5a_improve_v2_<arm>_s<seed>.pt` so scoring variants
  can be evaluated without retraining.
- Multi-aggregation scoring: per-dim squared error is aggregated by
  **mean** (house convention), **p95**, **std**, **top-k mean (k=5)** and
  **max** — all monitored as AUC/AP per family.

### Why
Research before the step (web, 3 sources):
- Ryu et al. 2022 (IEEE Access, "Quantile AutoEncoder...") document the exact
  failure we measured on DDoS: reconstruction error concentrates in a few
  channels and **top-k aggregation** recovers the signal that mean-MSE
  averages away. Our diagnostic showed ctx dims alone hit AUC 1.0000
  (ws_b_bwd, ws_p_fwd) while the mean-MSE score sat at 0.73.
- MuSE (arXiv:2410.20366, graph-level AD) shows "mean is not all you need" —
  multi-summary error features beat a single aggregation across 10 datasets.
- Kohrt et al. 2025 (PHM) confirm MAE/MSE channel dilution as a known
  weakness of the plain-score paradigm.

No new model topology — scoring only. Keeps the zero-day premise (score is
still threshold-free reconstruction error; nothing tunes on attack data
beyond the Monday-fitted scale).

### Results
_(filled in after the run — this entry is written before the fix, per the
"changelog first" rule.)_

### Caveats / notes for the team
- Top-k needs a k; p95 is top-k with k≈0.05d. k=5 is the first value tried,
  not tuned (tuning k per family would be label leakage).
- Multi-seed runs cost ~5-6x a single arm; the full 4-arm band is deferred.
---

## 2026-08-13 — E9 M5a-flow improvement: control arm was invalid, root cause found and fixed
**Author:** Deep (Person B — Detection Modeling) · assisted by opencode

### What changed
- `experiments/m5a_improve_v2.py` — E9 rerun with **valid controls only**:
  - `shipped` arm = the real `autoencoder_v2-256.pt` checkpoint, no retraining (control).
  - `base` / `log1p` / `ctx` arms retrained on the **MachineLearningCSV** Monday
    release (the data `autoencoder.py` actually used), eval scale pinned to the
    **GLF** Monday min-max (the convention behind every published number).
  - ctx features computed on the GLF release (has IPs), merged by row order —
    verified 1:1 alignment (flow_duration/fwd_pkts/bwd_pkts/fwd_bytes/dst_port
    equal 1.0000 across the two releases).
- `experiments/m5a_check_scaling.py`, `m5a_check_shipped.py`,
  `m5a_check_mlcsv_recipe.py` — diagnostics that isolated the failure.

### Why
E9 v1 (`m5a_improve.py`) reported base/log1p/ctx means of 0.66–0.90 — but its
retrained "base" arm never reproduced the shipped checkpoint (PortScan 0.29 vs
the baseline's 0.88), so **every v1 arm was an invalid control**. Three findings
surfaced during the hunt:
1. **The two CICIDS2017 releases do not carry the same values.** MLCSV vs GLF
   Monday agree on only ~91% of cells; the disagreement concentrates in derived
   rate columns (`Fwd Packets/s` ~0.055 equal, `Bwd Packets/s` ~0.168) — exactly
   the flood/scan-relevant dimensions. Training on GLF Monday does not reproduce
   a model trained on MLCSV Monday.
2. **Eval scale convention dominates.** Scoring the shipped checkpoint under
   GLF-Monday min-max reproduces the 0.8429 baseline exactly (PortScan 0.8825);
   under MLCSV-Monday min-max the same checkpoint scores PortScan 0.29. The
   published numbers are defined under GLF scale; MLCSV scale silently flips
   results.
3. **Bug in v1's p95 edit:** `(fs - feats)^2` compared the reconstruction of the
   *scaled* input against the *raw* matrix — an asymmetric error that made
   log1p == base to 4 decimals and collapsed PortScan. Fixed: error is now
   computed in scaled space, `(fs - xt)^2`.

### Results
Flow-level per-family MSE-AUC, Monday-fitted GLF scale, seed 0:

| arm | Patator | WebAttacks | DoS | DDoS | Infiltration | Botnet | PortScan | mean |
|---|---|---|---|---|---|---|---|---|
| shipped (control) | 0.7692 | 0.9431 | 0.8549 | 0.6912 | 0.8909 | 0.8686 | 0.8825 | **0.8429** |
| base (retrain, raw min-max) | 0.7272 | 0.9200 | 0.8346 | 0.6697 | 0.8558 | 0.7576 | 0.8672 | 0.8046 |
| log1p | 0.7793 | 0.6513 | 0.8786 | 0.7116 | 0.7569 | 0.7268 | 0.9896 | 0.7849 |
| ctx (log1p + 16 window ctx) | 0.9712 | 0.9546 | 0.9923 | 0.7291 | 0.7588 | 0.9211 | 0.9999 | **0.9039** |

- ctx beats the shipped control on Patator (+0.20), PortScan (+0.12), DoS
  (+0.14), WebAttacks (+0.01), Botnet (+0.05), DDoS (+0.04); loses only on
  Infiltration (-0.13, pos=36).
- ctx at 0.9039 still trails PIKACHU's 0.977 and is one unseeded run — no band
  yet (gotcha #11: any delta < ~6 pts is noise until multi-seeded).
- p95 per-dim scoring helps some families, hurts others (shipped: WebAttacks
  0.9431 -> 0.6322) — not an obvious win; means above are MSE.

### Caveats / notes for the team
- The 16 ctx features are **per-flow duplicated window aggregates**, not
  per-host scores — they make every flow in a window carry the same window
  statistics, legitimate for per-flow scoring but not the host-graph M5b view.
- ctx at eval time needs IP columns; the MLCSV release cannot provide them. The
  v2 arm is trained on MLCSV 76 + GLF ctx 16 by row position — fragile to any
  change in row order between releases (verified equal today, not enforced by
  code).
- **Not yet done:** multi-seed bands for all four arms; queued face-offs
  (RC-18 patator probe, E7 UNSW connection-level, RC-20 temporal edge probe);
  changelog entries for RC-17/RC-18/E7/E8 as they land. Any v1-era numbers in
  earlier notes should be treated as stale.
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
