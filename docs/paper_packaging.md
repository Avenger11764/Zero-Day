# Paper packaging — working notes (Deep, 2026-08-21)

Two papers, one artifact. Names below are placeholders; pick final ones with the
team. Everything maps to existing RC cards — no new experiments required for a
submission-quality draft of Paper A.

## Names (proposals)

- **Detector:** keep it descriptive + acronym-able. Candidates:
  *HOSTAGE* (HOST-graph Anomaly via Graph Autoencoder Evaluation) — memorable,
  slightly cute; *MW-SAGE* (multi-window SAGE); or plain "host-graph multi-window
  autoencoder (HGM-AE)". Decide by vote; consistency matters more than the pick.
- **Protocol:** *HELD-OUT* (Held-out-family Evaluation with Latent-band and
  rank-metrics for unsupervised NIDS)? Or simply "the CICIDS-HO protocol".
  The protocol name is the citation engine — protect it.

## Paper A — the detector (applied venue)

**Claim:** unsupervised host-graph detection with multi-window rank fusion
matches/beats the strongest published unsupervised result on CICIDS2017 with
error bars, replicates on two further dataset families, and beats re-run
non-relational baselines under identical conditions.

1. Intro — zero-day premise, AE-not-classifier decision, contributions list
2. Method — graphs (v2 features §RC-30), LogScaler (gotcha #14), GraphAE,
   60s+300s pure rank_mean fusion (RC-26; M5a exclusion justified there)
3. Evaluation protocol — held-out families, seed bands, unit/population rigor
   (cite gotchas #11/#16 as motivation), rank/recall@100 as operational metrics
4. Results:
   - Table 1: headline per-family AUC + attacker ranks (RC-30)
   - Table 2: fusion ablation incl. M5a-harmful finding (RC-26)
   - Table 3: baselines under identical conditions (RC-31)
   - Table 4: external replication IDS2018 (RC-29) + CTU-13 (RC-32)
   - Fig: P@100 structural cap (RC-27) — attacker prevalence vs achievable P@100
5. Adversarial robustness — evasion costs (RC-14; D to re-run on final config)
6. Limitations — calibration optimism, device sensitivity (#24), queue noise
   = drift (M6), saturated benchmark honesty
7. Related work — PIKACHU/AWTY, Anomal-E, EULER, AutoGraphAD face-off (RC-19)

Venue targets: Computers & Security, IEEE Access, DASC/PST/RAID workshop tracks.

## Paper B — the evaluation protocol (measurement/benchmark track)

**Claim:** how unsupervised NIDS should be evaluated; five failure modes we
found and fixed, each with a reproducible demonstration:

1. Unseeded comparisons are noise (±11-pt retrain band, RC-10)
2. Unit/population mismatches fabricate AUC 1.0000 (gotcha #16 history)
3. P@100 is structurally capped by attacker prevalence (RC-27) — propose
   rank/recall@100 reporting standard
4. Queue saturation ≠ detection failure (RC-18) — calibration vs recall
5. Contaminated "benign" halves poison training (LODO, RC-22)

Each failure mode = one section + one reproduction command from the repo.
This paper is the citation engine; write it second but design the artifact for
it now.

## Artifact checklist (blocks both submissions)

- [ ] One-command reproduce: `run_reproduce.ps1` → headline table from raw data
- [ ] Seeded end-to-end (set_seed everywhere; determinism flags documented)
- [ ] requirements.txt verified on a clean machine (cu128 pin just landed)
- [ ] Data download instructions for all three dataset families (CIC gated;
      CTU-13 direct URLs in eval_external_ctu13.py docstring)
- [ ] License + citation file (CFF) with the protocol name
- [ ] Multi-seed external results landed (running tonight) and folded into
      Tables 4 / protocol claims

## Open decisions for Deep

1. Final method + protocol names (team vote)
2. alert_pipeline default flip — after Avinash sign-off (RC-26 recipe)
3. Which venue first: A before B (safer FYP timeline) vs B first (citation play)
