# Overnight digest — session of 2026-08-13 (wake-up read)

Everything below is reproducible from the files it names. Full-summary source
of record = `experiments/report_cards.md` (RC-01…RC-24) + `docs/papers_profiles.md`.
No git commits were made (repo policy).

## Session close (evening of 2026-08-13) — flow-level chase, honest negatives, all queued runs complete

Added after the wake-up digest; covers E9 (M5a flow-level), RC-18, E7, RC-20.
Full detail in CHANGELOG.md (eight 2026-08-13 entries).

**E9 — M5a flow-level improvement, finished with a documented stop.**
Ctx window features (93 dims) lift shipped 0.8429 -> **0.9036 ± 0.0042**
(3 seeds; seeds 0.9039/0.9086/0.8983; best aggregate p95 0.9128 ± 0.0071).
Scoring variants exhausted: MAD-per-dim standardization is destructive
(Patator 0.9906->0.5838; label-leak trap on Infiltration), rank-transform
plateaus, plain top5/mean stay best. ctx2 concentration-ratio arm REJECTED
(0.8927 ± 0.0042; DDoS worsens 0.729->0.69). Per the pre-committed stop
condition (DDoS > 0.85 and mean > 0.93), flow-level retraining is STOPPED.
Against papers at flow level: PIKACHU 0.977 gap 0.073 NOT closed; Anomal-E
0.883 CLEARED (+0.021); EULER 0.757 / VGRNN 0.641 cleared.
`docs/papers_faceoff.md` updated. Ckpts `m5a_improve_v2_ctx_s{0,1,2}.pt`.

**RC-18 — Patator P@100 = 0.000 root cause found (not a detection gap).**
Tuesday's labels are direction-inverted: all 13,835 Patator rows are
src=172.16.0.1 (the FTP/SSH VICTIM server) -> 192.168.10.50. The attacker's
edges ARE ranked (best rank 11/702 in-window; 48/66 in window top-100); the
global top-100 is owned by 192.168.10.x internal chatter scoring 0.6938-0.6981
above the attacker's 0.680. Verdict: queue-calibration artifact.

**E7 — AutoGraphAD face-off at connection granularity: honest negative.**
Fixed three bugs (per-chunk scaling collapse, F1-inside-buckets 1.0 trap,
benign double-negation); final F1 macro **0.1731** / acc 0.9610 / bin AUC
0.8761; sim_k5 changes nothing (0.1728/0.9612/0.8762). AutoGraphAD 0.8423 bar
NOT cleared (-0.669); recorded as a loss plus the first same-unit unsupervised
comparison anyone published for it. `docs/papers_faceoff.md` row updated.

**RC-20 — temporal half REJECTED at edge granularity.**
Same covered edge set, block-stride host sequences (5 x 300s windows), fused
LSTM-block score vs graph node score at block end: fused mean AUC **0.568**
vs graph **0.706** (7 families: PortScan 0.603/0.293, DDoS 0.535/0.831, Botnet
0.825/0.746, Infiltration 0.593/0.592, WebAttacks 0.267/0.754, Patator
0.424/0.866, DoS 0.732/0.863). The host-level +0.0005 "null" is now a
directional negative: the sequence half does not contribute signal we can
defend. Thesis line: structural half carries M5b.

**State:** every queued run complete and recorded; no commits (repo policy);
working tree has uncommitted experiment scripts the user may push. GPU idle.
## What the night established

0. **RC-15 — ablation table is finally fresh.** `ensembler.py --limit 0 --seed 0`
   (the CLAUDE.md #1 outstanding item): fused_rank_max **0.9535** (was 0.9567
   on stale 150k — same winner), M5b 0.9238 (+0.007 on full data), fused_mean
   0.9171, fused_max 0.8751, M5a 0.8417. Headline survives; `ablation_table.md`
   regenerated. M5b now scores its old weak spots best at node granularity
   (WebAttacks 0.9569, Patator 0.9568).

1. **RC-10 — the honest uncertainty band.** The shipped stack was retrained 5×
   (seeds 0–24, 300s): agreement mean-AUC **0.8034 ± 0.109**, M5b alone
   0.8170 ± 0.130. Every published number carries a ±10–13-pt retrain band; the
   shipped anchor (0.8304/0.8391) was a fair draw. Stable facts that survive:
   **Patator agreement P@100 = 0.000 ± 0.000** (gate weak spot, real);
   agreement lifts DDoS P@100 (0.748 vs 0.656). Checkpoints: 5 ×
   `experiments/seed_checkpoints/ensemble_seed{0,5,10,15,20}.pt`.

2. **RC-11 — UNSW transfer (E5): the scaler is the lever.** Shipped weights on
   NF-UNSW-NB15-v2 (the AutoGraphAD release): zero_shot **0.5816** →
   refit_scaler **0.8362** → finetune 0.8798 → target_only 0.8946 (host AUC).
   Refitting `NodeScaler` on the new network's benign = ~85% of the retrain
   ceiling at zero training cost. **Caveat: the release has 40 src IPs; all 9
   families = same 4 attackers; per-family numbers degenerate; F1 vs
   AutoGraphAD 0.8423 is not comparable at host granularity** — report AUC only.

3. **RC-12/13/16 — sim edges (E4 → E4b → k=20): the lever is fully confirmed
   and monotone.** Pooled mean AUC k=0 0.8284 / k=5 0.8481 / k=20 0.8581 over
   3 independent retrains each; WebAttacks 0.851→0.956, Patator 0.919→0.963,
   Botnet 0.609→0.714 at k=20 while DDoS 0.929→0.852 and DoS 0.967→0.900 pay.
   **P@100 peaks at k=5 (0.255) and collapses at k=20 (0.216).** Would ship as
   k=5 only, and does not ship yet (build-path change, D/demo call).

4. **E2/E3 (same day) closed the gate/fusion/window axis** at 0.8304–0.8391.

5. **Papers DB is current for viva questions: 31 profiles, coverage through
   2026-08-10** (batch 2 = 16 papers incl. AutoGraphAD, HybridSAGE AUC 0.9957,
   QIHHO-GTrNIDS 2026-08-10, SKGFusionKAN arXiv:2607.02981, RLD/FPC at
   arXiv:2607.01194). DRIFT-CL stayed out (unverifiable).

## Running / pending at wake-up

- **Nothing running — every queued experiment is complete and recorded.**
- k=20 confirmation done (RC-16): sim-edge lever is fully confirmed and
  monotone (k=0/5/20 pooled AUC 0.8284/0.8481/0.8581); P@100 peaks at k=5 and
  collapses at k=20 (0.216); would only ever ship as k=5 and does not ship yet
  (build-path change = D/demo call).
- Report cards RC-08…RC-16 are the complete summary source; ablation_table.md
  is regenerated (RC-15, was the last stale headline). Harness results in
  `harness/results/m5b_evasion.md` (RC-14).
- Report cards RC-08…RC-14 are the full-summary source. Remaining from
  CLAUDE.md's list: nothing GPU-bound is queued; the push of the working tree
  is a user decision (check `git status`, never commit without asking).
- Feature-set v2 grid + IDS2018 transfer earlier: v2 is a blunt tie with v1
  (0.9448 vs 0.9453 node AUC) — CLAUDE.md's "biggest lever" note is stale;
  transfer protocol for IDS2018 exists in `transfer_eval.py`.

## Bugs found & fixed this session (in-experiment, not in shipped code)

- E4: edge-model device mismatch (CPU tensor → CUDA weights); `argpartition`
  kth-out-of-bounds on small windows — both fixed in `sim_edges.py`.
- E5: UNSW v2 `Label` is binary 0/1 (not Benign/Attack strings); loaded
  ensemble members need explicit `.to(device)`.
- Shell quirk: `Start-Process` via the tool prints a bogus `ChildProcess.kill`
  error — the process DOES start; verify by process list, never relaunch
  (cost us a duplicate E1 launch earlier).

## Operational notes

- Graphs: 31 GB RAM / 16 cores / RTX 3090; shell not elevated; nothing needed
  admin. Background runs must print with `flush=True` (redirect buffering hid
  E5's progress).
- Data note for A: `data/NetFlow/NF-UNSW-NB15-v2.csv` (442 MB) is the
  AutoGraphAD/Anomal-E benchmark file; `NF-CSE-CIC-IDS2018-v2.csv` (3.2 GB) is
  the same release for 2018 (also no timestamp column).