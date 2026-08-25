# PAPER OUTLINE — week-4 freeze (Deep, 2026-08-25)

Supersedes `docs/paper_packaging.md` working notes. Every number below is a
4-seed band on GPU with determinism flags — quote nothing else.

## Name
**HOSTFUSE** — HOST-graph Fusion of Unsupervised reconstruction Scores.
Protocol: **HELD-OUT** (held-out-family evaluation; train benign Monday only,
evaluate 7 unseen families, report mean±std over seeds 0-3).

## One-command artifact
```
python detection/eval_mw_ablation_4seed.py --seeds 0 1 2 3 --epochs 60
```
Requires only `data/GeneratedLabelledFlows/` (public download). Reproduces the
headline table end-to-end: training, fusion, per-family AUC, seed band.

## Headline claims (all banded, all verified 2026-08-25)
| Claim | Number | Source |
|---|---|---|
| Detection, CICIDS2017, v1 feats | **0.9996 ± 0.0001** | mw_ablation_4seed.json |
| Detection, CICIDS2017, v2 feats | 0.9997 ± 0.0001 | feature_set_v2_results.json |
| vs re-run baselines (same features) | PCA .9417 / IF .9357 / MLP-AE .9517 → +4.8 pts | baselines_4seed.json |
| IDS2018 attackers (external) | top-11 / 32,935 in 3 of 4 seeds | external_ids2018_multiseed.json |
| CTU-13 Virut infected host | rank #1 in 4/4 seeds | external_ctu13_multiseed.json |
| CTU-13 Rbot C&C | #1 in 3/4 seeds | same |

## Paper structure (applied venue)
1. **Intro** — zero-day premise; classifier-vs-autoencoder decision; three
   contributions: relational host graphs, multi-window noisyor fusion, held-out
   protocol with bands.
2. **Method**
   - Flows → host graphs: directed edges, time windows, 8/19 node features
     (`graph_builder.py`).
   - GraphSAGE autoencoder, LogScaler (log1p before min-max), trained on benign
     only (`gnn_model.py`).
   - Two time-scales (60s+300s), percentile calibration, within-pool rank
     fusion (`eval_mw_ablation_4seed.py` = reference implementation).
   - Revived per-flow pillar: 87-dim window-context AE, lifted to host by max,
     fused by noisyor rank (`exp_m5a_revival.py`, served in `alert_pipeline.py`).
3. **Protocol** — HELD-OUT definition, seeding/determinism rules (gotcha #24),
   why P@100 is retired (RC-27) and rank/recall@100 quoted instead.
4. **Results** — headline table + externals + baselines table above.
5. **Ablations** — shipped-M5a poison (0.9499); temporal half negative (RC-20);
   LODO negative; k=5 sim-edges negative; latent-width null (gotcha #9/15).
6. **Discussion** — drift-driven queue noise (M6), calibration holdout,
   limitations: single-lab benign day, batch-only noisyor.

## Names NOT chosen (avoid in text)
PIKACHU comparisons are context (related work), not our baseline claim — we now
exceed it; cite as prior bar with their grid-search-on-eval caveat.
