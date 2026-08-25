# GNN vs Fused — Two-Experiment Plan (deep/detection-work)

**Date:** 2026-08-25
**Branch:** `deep/detection-work` (isolated from `main`)
**Question:** `detection/gnn_model.py` (graph-only, prod) vs `detection/gnn_temporal_fused.py` (graph+LSTM, "proper" M5b)
**User-reported gap (RC-20, edge-level on covered set):** fused wins PortScan (+0.31) & Botnet (+0.08), loses DDoS (−0.30), Patator (−0.44), WebAttacks (−0.49). Mean graph 0.706 vs fused 0.568.

---

## First Principles Audit — Why Fused *Should* Help, Why It Currently Doesn't

### What fused is supposed to catch (design intent in `gnn_temporal_fused.py:26`)
- A single host-communication graph is a snapshot: "backup server fans out to 200 peers at 02:00" looks identical to "laptop that never did that just started". Only the **sequence** separates stable vs change.
- That is the slow-and-gradual attacker the red-team harness simulates (`harness/graph_techniques.py: slow_scan` evades at 50 windows if you stretch).

### Why it doesn't (evidence from repo)
1. **No LogScaler (critical).** `gnn_model.py:111` `NodeScaler` is plain min-max. Every published headline since 2026-08-12 uses `LogScaler = log1p → min-max` (+0.16 AUC at 60s, Patator 0 → 0.618, WebAttacks 0 → 0.381 per gotcha #14). `gnn_temporal_fused.py:59` imports `NodeScaler` directly → fused has never had the single biggest win. RC-20's both arms were trained without log at 300s/100ep, so its −0.14 is partly a scaling artefact.

2. **Coverage collapse.** Fused needs a host in ≥5 *consecutive* windows (`SEQUENCE_LEN=5`). Quick check on this machine (RTX 3090):
   - Monday benign, 60s: 9709 hosts → only **435 hosts (4.5%)** have ≥5 consecutive windows (mean run 2.2, max 244).
   - RC-20 coverage: 10–22% of *edges* (hosts that survive filtering). Fused is scored on a tiny, biased slice; GNN scores everyone.
   - Genuine bursts (single-window attacker) are invisible by construction — noted as complementarity in 2026-08-11 entry.

3. **8 features only, stale bottleneck.** Fused uses 8-dim nodes. Since 2026-08-21 `feature_set="v2"` (19 dims, indices 0–7 stable) lifts Botnet 0.933→0.999 (+6.6pts) on graph-only and is capacity-controlled (latent 19 ≈ same). Fused never got v2.

4. **Joint end-to-end training non-stationarity.** `gnn_temporal_fused.py:156` rebuilds sequences *each epoch* from the current GNN embeddings (`build_host_sequences` called inside loop). Only LSTM gets stable gradients if embeddings shift; loss is noisy and convergence is seed-sensitive (gotcha #11: ±6pts noise).

5. **Temporal encoder choice untested.** LSTM seq2seq reconstructs *features* (not embeddings) to avoid identity map (`gnn_temporal_fused.py:37`). Temporal alternatives (Transformer, TGN, simple temporal pooling, EvolveGCN-style parameter evolution) never tried.

6. **Window/scale interaction.** RC-20 used 300s to get 5+ windows cheaply. 60s (prod default for P@100) vs 300s changes graph count (Monday 487 vs ~98) and coverage. Fused at 60s/T=5 starves; at 300s it sees longer history but coarser dynamics.

**Prediction:** fixing (1) alone should close ~half the gap; (1)+(2)+(3) should flip sign.

---

## Research Summary (web, 2026-08-25)

- **NVIDIA Morpheus GAE (May 2025):** Graph U-Net hierarchical embeddings + global edge embeddings + edge-existence probability as anomaly score; beats Anomal-E. Lesson: edge-aware + multi-resolution helps; our fused ignores edges entirely (reconstructs node features only).
- **TGN / TGAT / EvolveGCN (Rossi 2020, Pareja 2020):** TGN uses LSTM memory per node for streaming edges; TGAT uses temporal self-attention (quadratic in neighborhood × horizon); EvolveGCN evolves GCN parameters via RNN. All report +40% latency win vs static, but need dense states per node (O(|V|d) memory) and suffer gradient pathologies over long sequences. Lesson: for CICIDS17 windows (487 graphs/day, 9709 hosts), per-host LSTM memory is feasible but attention is expensive.
- **TAGAE / AutoGraphAD (2025-2026):** Temporal-attentive VGAE with reconstruction + KL weighted score `Score = α·L_feat + β·L_struct + γ·KL`, Robust Scaling of errors, heterogeneous graphs. Lesson: weighted multi-term scores beat plain MSE; our fused uses single MSE over all dims (channel dilution confirmed in ctx diagnostics).

**Adopt:** LogScaler + v2 first; then rank-level fusion (already beats value-level per gotcha #17); avoid per-family tuning (zero-day premise).

---

## Experiment 1 — Combine GNN + Fused (ensemble)

**Goal:** win on *all* families by using each model where it is strong.

**Baselines (already measured):**
- Graph alone (edge-level, covered set): 0.706 mean
- Fused alone: 0.568 mean

**Fusion arms (zero-day clean, no label tuning):**
| Arm | Rule | Rationale |
|-----|------|-----------|
| `rank_mean` | mean of normalized ranks over union | Gotcha #17: only rank-position fusion beats both (vs raw values) |
| `rank_max` | max rank | Robust when one detector spikes |
| `coverage_gate` | fused score if host has ≥T windows else GNN | Honest about missing history |
| `max` / `mean` (value) | controls | Should lose (gotcha #20/21) |
| `weighted` | 0.7·GNN + 0.3·Fused (rank space, grid-searched on *benign Monday only*) | Cheap learned weight |

**Metric:** host-window ROC-AUC per family on IDENTICAL host population (intersection of both models' coverage for fair comparison, plus union for operational). Report coverage %.

**Stop if:** any ensemble beats GNN on ≥6/7 families and mean > GNN+0.02 with band outside ±0.06 (gotcha #11 noise floor).

---

## Experiment 2 — Make Fused Beat GNN Alone

**Goal:** single fused model > GNN alone on mean AUC (fair, same host population).

**Staged fixes (ordered by predicted effect, one variable at a time):**
1. **LogScaler** (`log1p → min-max`, default since 2026-08-12) — replaces `NodeScaler` in fused.
2. **Feature set v2** (19 dims) — `feature_set="v2"` in `build_graphs`.
3. **Coverage:** T=3 vs T=5, plus 300s vs 60s windows (T=3/60s gives ~3× coverage).
4. **Two-stage training:** freeze GNN after pre-train (200ep) → train LSTM only vs joint. Stable embeddings.
5. **Temporal encoder swap:** LSTM vs Transformer (1-layer, 4-head) vs mean-pool + MLP (ablation).
6. **Loss weighting:** per-dim MSE weighting by benign variance (addresses channel dilution from ctx diagnostics).

Each stage is a branch; only the winner advances. Report per-family Δ and coverage.

**Budget:** RTX 3090, cu128, CUDA-deterministic. Limit 150k for smoke, full files for headline. 4 seeds for any claimed win (±6pt noise).

---

## Headless Runner

- `detection/exp_gnn_fused_ensemble.py` — Exp 1, emits `experiments/exp1_*.json` + markdown scorecards.
- `detection/exp_fused_improve.py` — Exp 2 stages, emits `experiments/exp2_*.json`.
- `run_exps_loop.ps1` — loops until user stops, picks next untested arm, logs tabular scorecard after each run.
- Machine stays on 24/7; loop is idempotent (skips completed arms, resumes on restart).

**Scorecard format (required by user):** markdown table per run: family × (GNN, Fused, each fusion) AUC + mean Δ + coverage + winner.

---

## Conventions for this branch

- Never edit `CHANGELOG.md` history; append only.
- Never push `Knowledge/`.
- Device + torch build stated on every number (RTX 3090, torch 2.11.0+cu128, deterministic flags).
- Commit trailer `Assisted-by: opencode/muse-spark-1.2`.

## Next step

Run smoke baselines (limit 150k, seed 0) to reproduce RC-20 gap on this machine before any fix.
