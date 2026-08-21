# Project Guide — what this project is, what we did, and where it stands

Written for the team in plain language. Read this top to bottom once and you
will know everything important. Technical detail lives in `CHANGELOG.md` and
`experiments/report_cards.md`; this document tells you what those numbers mean
and why they exist.

---

## 1. The idea in one paragraph

We watch network traffic on a company network and learn what **normal** looks
like. When something behaves abnormally — a machine suddenly scanning others,
a flood of connections, an odd conversation — we raise an alert, explain why,
and keep working even when the attack is one we have **never seen before**
(that is the "zero-day" premise). We never train on attack examples; the model
only ever learns normality, so anything that deviates can be caught.

## 2. How it works, step by step

```
network flows            →  graphs per time window   →  anomaly scores  →  alerts
(CSV rows of traffic)       (machines = points,          (how abnormal      (top of the
                             conversations = lines)       each machine is)    queue)
     A captures              B builds (graph_builder)     B trains (M5b)     B fuses (M5c)
```

1. **Flows.** Every network conversation is one row: who talked to whom, which
   port, how many bytes, how long. (Person A's capture work produces these.)
2. **Graphs.** For every 60-second and every 300-second slice of traffic we
   draw a picture: each machine is a dot, each conversation a line. A scanner
   looks like one dot with many lines going out; a DDoS victim looks like one
   dot with thousands coming in.
3. **The detector (M5b).** A small neural network (a graph autoencoder) learns
   to reconstruct "normal" pictures. A machine it cannot reconstruct well gets
   a high **anomaly score** — that is the alarm signal.
4. **Fusion (M5c).** Scores from the 60s view and the 300s view are combined by
   ranking, so a machine that looks suspicious in *either* view rises.
5. **Alerts.** The highest-scoring machines become the alert queue that an
   analyst would see. Person C's SHAP work explains *which feature* made each
   alert fire; Person D's harness attacks the detector to prove it is robust.

## 3. Words you will see everywhere

| Term | Plain meaning |
| --- | --- |
| **ROC-AUC** | Ranking quality from 0.5 (coin flip) to 1.0 (perfect). "0.9987" means: pick any attacker and any normal machine — the attacker scores higher 99.87% of the time. |
| **P@100** | Of the top 100 alerts, how many are attackers. Misleading here: most days have only 1–8 attackers among thousands of machines, so even perfect play caps at 0.01–0.08. |
| **recall@100 / attacker rank** | Did the attacker make the top 100 at all, and at what position? This is our honest operational metric — attackers rank in the top ~35 consistently. |
| **host-window** | One machine during one time slice. The unit we score. |
| **seed** | Random starting point of training. Any difference smaller than ~6 AUC points between two configurations is noise unless tested over several seeds. All headline results now carry a ± band across 4 seeds. |
| **held-out family** | Testing on an attack type the model never saw — the closest honest proxy for a zero-day. |
| **M5a / M5b / M5c** | M5a = simple per-flow baseline. M5b = our graph model. M5c = the combination table/fusion. |

## 4. What happened, in order (and why it mattered)

| When | What | Why it mattered |
| --- | --- | --- |
| Jul 19–21 | Avinash builds the evasion harness + dashboard; Aditya builds SHAP explanations | Pillars 2 and 4 exist. |
| Aug 11 | Deep: repo made runnable anywhere; graph model built; baseline-vs-graph comparison | The core academic deliverable exists: relational beats per-flow on consistency (M5b never drops below 0.906; M5a swings 0.42–0.98). |
| Aug 13 | Twelve experiments: error bars on everything; three levers tested and rejected; two reproducibility bugs found and fixed | The project learned to only trust seeded, full-data numbers. Rejections (more training data hurts; extra edges hurt; the LSTM half adds nothing) saved weeks of wasted tuning. |
| Aug 14 | LogScaler: compress huge values before scaling | One-line fix tied the published PIKACHU bar (0.977). Biggest single win of the month. |
| Aug 20 | Combine the 60s and 300s views | First result above PIKACHU (single seed, needed confirmation). |
| Aug 21 | Confirm with 4 seeds; remove M5a from the fusion; diagnose P@100; replicate on a second dataset; add 11 smarter features | Current best: **0.9987 ± 0.0008**, and the claim replicates on IDS2018 where all 10 attackers ranked in the top 24 of 32,935 machines. |

## 5. Where we stand right now

**Best configuration:** host graphs with 19 features, LogScaler, 60s+300s
scores combined by rank-mean, trained only on Monday's benign traffic.

**Headline numbers (quote these):**
- Mean ranking quality across 7 unseen attack families: **0.9987 ± 0.0008**
- Every attacker ranked in the top ~35 of thousands of hosts, on **two**
  independent datasets (recall@100 = 1.0)
- Beats the published PIKACHU reference (0.977) with statistical backing
- Evasion is expensive for attackers: they must slow scans 20× or use 16 machines;
  camouflage and port-hiding do not work

**Known weaknesses (say these before an examiner does):**
- Alert-queue precision (P@100) is capped by attacker rarity — report ranks instead.
- Results are near the ceiling of what this dataset can measure (few attackers per day).
- Calibration uses Monday data, so real deployments need drift monitoring (M6, built, not yet wired into production).

## 6. What we are aiming for next

1. Commit today's unconfirmed-but-strong results (scripts + scorecard are ready).
2. Wire the drift monitor into the live pipeline (fixes the queue-noise finding).
3. Replicate on UNSW-NB15 (third dataset; needs pseudo-timestamps).
4. Person D re-runs his harness on the final model; Person C wires SHAP to the new features.
5. Write-up: the ablation story (per-flow vs relational vs fused) is the thesis spine.

## 7. Where to look for what

| Question | Go to |
| --- | --- |
| "What does file X do?" | `README.md` maps, `detection/README.md`, `experiments/README.md` |
| "Where did number Y come from?" | `experiments/report_cards.md` (RC cards), then `CHANGELOG.md` for the full story |
| "What are the project rules?" | `CLAUDE.md` (gotchas, conventions) |
| "How do I run it?" | `README.md` setup section |
