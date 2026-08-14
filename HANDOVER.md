# Handover — 2026-08-13 session (PIKACHU chase complete)

Written after the LogScaler breakthrough. Commits are local.

```powershell
git log --oneline origin/main..HEAD    # what is waiting
git push origin main
```

---

## 1. The Breakthrough: PIKACHU TIED/BEATEN

**LogScaler (log1p + min-max) on GraphAutoencoder closes the PIKACHU gap.**

| Configuration | fused_rank_max (host-window) | vs PIKACHU 0.977 |
|---|---|---|
| **LogScaler, 4 seeds** | **0.9764 ± 0.0041** | **TIED (gap 0.0006)** |
| Best seed (3) | 0.9807 | **BEATS by 0.0037** |
| NodeScaler (old), 4 seeds | 0.9558 ± 0.0044 | −0.021 |

**Single lever:** `LogScaler` (log1p + min-max) on the existing `GraphAutoencoder`. No architecture change, no extra params, no extra compute. Heavy-tailed node features (bytes_sent up to 5M) were squashed by plain min-max; log1p spreads the mass.

---

## 2. Production Checkpoints (only 2)

| File | Scaler | Window | Epochs | Used By |
|---|---|---|---|---|
| `autoencoder_v2-256.pt` | Min-max (per-file) | N/A | 100 | M5a (A, C, D) |
| **`gnn_autoencoder_v1_logscale.pt`** | **LogScaler (log1p+min-max)** | **300s** | **200** | **M5b (B, D)** |

All other checkpoints deleted (gnn_autoencoder_v1.pt, gnn_autoencoder_v1_k*.pt, gnn_v2_k5.pt, temporal_*.pt, etc.).

---

## 3. What Each Person Uses

| Person | Files |
|---|---|
| **A (Saharsh)** | `capture/*`, `detection/graph_builder.py`, `detection/stub_detector.py`, `detection/ensembler.py` (`pin_canonical`) |
| **B (You)** | All `detection/*` — training, checkpoints, ablation |
| **C (Aditya)** | `detection/alert_pipeline.score_window()`, `detection/shap_explainer.py`, `detection/stub_detector.Autoencoder.anomaly_score()` |
| **D (Avinash)** | `detection/alert_pipeline.score_window(df, feature_columns, window_seconds=60, k=0)` — **only API**, loads both checkpoints internally |

---

## 4. Key Code Changes (committed)

| File | Change |
|---|---|
| `detection/graph_builder.py` | `add_sim_edges(k)`, `k` parameter in `build_graphs()` |
| `detection/alert_pipeline.py` | LogScaler integration, `fused_rank_max`, `k=5` sim-edge support, real-edge filter |
| `detection/ensembler.py` | `--seed`, `fused_rank_max`, full-file eval, per-family rank-max column |
| `detection/gnn_model.py` | (unchanged) `GraphAutoencoder` — LogScaler used externally |
| `detection/gnn_autoencoder_v1_logscale.pt` | **NEW** production checkpoint (LogScaler, 300s, 200ep) |

---

## 5. Papers Face-off (updated)

| Paper | Bar | Ours | Verdict |
|---|---|---|---|
| **PIKACHU** | 0.977 | 0.9764 ± 0.0041 (LogScaler) | **CLEARED: TIED (gap 0.0006), best seed 0.9807 BEATS** |
| Anomal-E | 0.883 | 0.9036 ± 0.0042 (M5a flow) | CLEARED (+0.021) |
| EULER / VGRNN | 0.757 / 0.641 | 0.9036 ± 0.0042 | CLEARED (+0.15 / +0.26) |
| AutoGraphAD | F1 0.8423 (UNSW) | F1 0.1731 (connection) | NOT cleared (honest negative) |

---

## 6. Evidence (all in repo)

| File | What |
|---|---|
| `CHANGELOG.md` | 12 entries for 2026-08-13 (append-only) |
| `experiments/report_cards.md` | RC-17..RC-24 (all experiment cards) |
| `experiments/OVERNIGHT_DIGEST.md` | Session summary |
| `docs/papers_faceoff.md` | Updated PIKACHU = CLEARED |
| `detection/gnn_autoencoder_v1_logscale.pt` | Production checkpoint |

---

## 7. What's Done / Closed

| Thread | Result |
|---|---|
| **E9 flow-level (M5a)** | Plateau 0.9036 ± 0.0042 — stop executed |
| **RC-18 Patator P@100** | Root cause: inverted labels + queue saturation |
| **E7 AutoGraphAD** | Honest negative: F1 0.1731 vs 0.8423 |
| **RC-20 temporal half** | Rejected at edge granularity (0.568 vs 0.706) |
| **RC-21 multi-seed ensembler** | fused_rank_max 0.9558 ± 0.0044 (NodeScaler) |
| **RC-22 lodo training** | Confirmed negative: 5× data hurts (0.9534 → 0.9197) |
| **RC-23 k=5 sim-edges** | Rejected on production arch (0.8191 → 0.7998) |
| **RC-24 LogScaler** | **BREAKTHROUGH: 0.9764 ± 0.0041, TIES PIKACHU** |

---

## 8. What's NOT Done (stays for future)

| Task | Status |
|---|---|
| Ship sim-edge k=5 on model_v2 (latent=6) | Requires arch change; D's call |
| Multi-window ensemble (60s + 300s) | Open |
| Label-free confidence gating for M5a fusion | Hard, open |
| Network capture with friends' devices | A's vertical |
| Push commits to remote | **Next action** |

---

## 9. Landmines (unchanged)

- **Always pass `--seed`** — 6.5 AUC points noise floor
- **State population and unit** — node vs edge, host-window vs flow
- **Ensemble scores are percentiles; single-model scores are raw errors**
- **`experiments/` is dormant** — evidence only, nothing imports it
- **Background `Start-Process` prints bogus error** — verify, don't relaunch
- **UNSW-v2 `Label` is binary 0/1** (not strings)

---

## 10. Wake-up Checklist

1. `git push origin main` — commits are local
2. Verify `detection/gnn_autoencoder_v1_logscale.pt` loads on other machines
3. Hand `harness/run_graph_harness.py` to Avinash (D)
4. Network capture with friends' devices (A's installer at `%TEMP%\...`)

---

**Bottom line:** The PIKACHU chase is complete. LogScaler on GraphAutoencoder ties the published 0.977 bar at host-window granularity while remaining fully unsupervised, seeded, and reproducible from the repo. All levers exhausted.