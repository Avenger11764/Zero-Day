# Research paper profiles — 15 papers from Papers.xlsx

Read 2026-08-13 (two parallel literature passes). One section per paper, with
exact numbers, comparability warnings, reproduction effort, numbers to beat,
and research gaps our project can claim. Source sheet:
`C:\Users\trex2\Downloads\Papers.xlsx`.

Legend for effort: **Low/Medium/High** = effort to reproduce on OUR local data
(CICIDS2017 full files, CSE-CIC-IDS2018, UNSW-NB15 netflow). "Numbers to beat"
states the precise bar for claiming superiority — most papers measure
different metrics (F1 vs AUC vs ASR), so state the metric in every claim.

---

## 1. Deep PackGen — DRL adversarial packet generation
**Hore, Ghadermazi, Paudel, Shah, Das, Bastian · ACM TOPS 2025 (arXiv:2305.11039)**

- **Method:** DDQN agent perturbs RAW FORWARD packets (1,525 byte-features of
  IP/TCP headers + payload) to evade a surrogate ensemble (LR+DT+MLP, ~99% acc
  each). Functional constraints respected (checksums, header validity). Tested
  against UNSEEN classifiers: DT, RF, MLP, DNN, SVM.
- **Data:** CICIDS2017 + CICIDS2018 PCAPs (Heartbleed/Botnet excluded, too few
  forward packets).
- **Headline:** ASR (attack success rate) avg **0.664 on CICIDS2017**
  (Table 9), **0.398 transferred to CICIDS2018** (Table 10). >45% of successful
  adversarial samples were out-of-distribution (K-S test).
- **Reproduce:** Medium-high. Needs raw PCAPs + packet parsing; we hold only
  flow CSVs. Their classifiers are supervised per-attack models — orthogonal
  to our unsupervised AE.
- **To beat:** no directly comparable number (packet-classifier ASR). If we
  ever target packet-level detection: DT evasion >0.96 is the bar.
- **Gaps we can claim:** no graph-NIDS target, no anomaly/AE detectors tested,
  no defence evaluation, no latency budget.
- **Applies to us:** their perturbation recipe (functional, forward-only) is
  the red-team standard our flow-feature mutations lack (harness seam for D).
  OOD finding = drift monitor (M6) is the principled defence.

## 2. Problem-space structural adversarial attacks on GNN-NIDS
**Venturi, Stabili, Marchetti · arXiv:2403.11830 (2024)**

- **Method:** formalises C2x/U2x edge-injection attacks on flow graphs (hosts =
  nodes, flows = edges): inject β benign-looking edges from a compromised node
  (C2x) or clean node (U2x). Targets E-GraphSAGE and LineGraphSAGE binary
  detectors. Problem-space constraints respected (real netflows).
- **Data:** CTU-13 (5 botnet variants), ToN-IoT. 1:10 malicious:benign blend.
- **Headline:** E-GraphSAGE **collapses at β=1** on botnets (F1 0.942 baseline
  CTU-13, 0.978 ToN-IoT); LineGraphSAGE survives to β>5. ToN-IoT DoS models
  unaffected (too few compromised test nodes).
- **Reproduce:** Medium on CICIDS2017: re-implement C2x/U2x on our per-window
  graphs; report AUC-drop under injection (their metric is DR at fixed β, not
  directly comparable).
- **To beat:** no published AUC-under-injection number for CICIDS2017 — first
  is claimable.
- **Gaps:** no defences evaluated; no AE-GNN-NIDS target; binary only.
- **Applies to us:** this IS our threat model. D's harness should implement
  C2x/U2x exactly; our edge-alert pipeline is the unit under test.

## 3. GNN for malicious attack detection — systematic review
**Alshehri, Sharaf, Molla · MDPI Information 16(6):470 (2025)**

- **Method:** PRISMA review, 28 studies (2020–2025) classified by dataset,
  architecture, domain. Narrative synthesis.
- **Headline:** pooled AUC ≈0.94 (95% CI 0.92–0.96, I²=78%) per third-party
  summary — NOT verified against full text. GCN 42% / GAT 25% / GraphSAGE 18%.
- **Reproduce:** N/A (review).
- **To beat:** none. Context only: our whole-file mean 0.9300 sits in that
  range.
- **Gaps:** evaluation standardisation is the field's open problem — our
  per-family, seeded, stated-population protocol is the answer to it.

## 4. Always be Pre-Training — few-shot GNN-NIDS
**Gu, Lopez, Alrahis, Sinanoglu · arXiv:2402.18986 (2024)**

- **Method:** dense categorical embeddings + in-context SSL pre-training
  (DGI-style contrastive) then fine-tune on few labels. Backbone E-GraphSAGE.
  Hosts=nodes, flows=edges, undirected. log1p transform on right-skewed
  features (independently validates our gotcha #14!).
- **Data:** ToN-IoT (461k records), NF-UQ-NIDS-V2 (76M records — NetFlow
  standardisation of UNSW-NB15 + ToN-IoT + CSE-CIC-IDS2018 + BoT-IoT).
- **Headline:** SSL pre-training +8.32% F1 (ToN-IoT), +0.87% (NF-UQ); with
  **3.7% labels: F1 93.22% (ToN-IoT) / 84.64% (NF-UQ)** = >98% of supervised
  ceiling.
- **Reproduce:** High. NF-UQ-NIDS-V2 overlaps our local datasets; PyG recipe
  portable to our autoencoder pipeline. Undirected (our design is directed).
- **To beat:** micro-F1 93.22% / 84.64% at 3.7% labels — but F1 ≠ AUC; run
  their protocol if we adopt this track.
- **Gaps:** no temporal models, no drift, no adversarial, undirected only.
- **Applies to us:** SSL pre-train on unlabeled deployment traffic is
  compatible with our "Monday normality" training story; log1p citation.

## 5. Are We There Yet? — reproducibility of graph NIDS (GIDS)
**Wang, Zheng, Gui, Hua, Hassan · arXiv:2503.20281 (2025)**

- **Method:** reproduction + replication of 5 GIDS (Anomal-E, VGRNN, PIKACHU,
  EULER, ARGUS) with grid-search; evasion robustness (edge injection, K
  edges); scalability.
- **Data:** LANL, DARPA OpTC, **CIC-IDS-2017**, plus new enterprise dataset.
- **Headline (CIC-IDS-2017, Table 5):** PIKACHU **AUC 0.977 / AP 0.872**;
  Anomal-E 0.883; EULER 0.757; VGRNN 0.641. **Evasion: 2 adversarial edges
  fully defeat VGRNN/EULER/ARGUS on LANL** (r_atk→1.0 at K=2).
- **Reproduce:** Medium-high. Same dataset + same metric family (AUC/AP/TPR/
  FPR) — the MOST comparable external benchmark. Verify their CICIDS2017 graph
  construction before claiming direct comparison.
- **To beat:** **PIKACHU AUC 0.977 / AP 0.872 on CIC-IDS-2017** — the strongest
  published number on our headline dataset. Our node-level 0.9300 (per-family,
  seeded) is competitive except vs PIKACHU.
- **Gaps:** LANL-centric; CICIDS2017 shows systematic generalisation failure;
  evasion on 3 models only; no defences proposed.
- **Applies to us:** edge-injection red team (2 edges = total defeat of 3
  SOTA models on LANL); the "high FPR hardens evasion" paradox (their RQ3) —
  do not raise thresholds without re-testing evasion; window size is
  first-order (supports gotcha #8 and today's 300s finding).

## 6. Neuro-Symbolic AI for cybersecurity — review
**Hakim, Adil, Velasquez, Xu, Song · arXiv:2509.06921 (2026)**

- **Method:** systematic review of 103 publications, three-tier taxonomy,
  G-I-A lens.
- **Headline:** KnowGraph (logic-rule-guided GNN) inductive AUC **0.9112** vs
  EULER 0.8973 on LANL; at 0.5% FPR plain GNN TPR→0 while KnowGraph keeps
  ~35% TPR. Multi-view GNN +10.6% F1 on ToN-IoT/UNSW-NB15. 42% pass@5
  zero-day exploitation by autonomous offensive systems.
- **Reproduce:** low (review). Anchors: LANL AUC 0.9112 (KnowGraph).
- **To beat:** LANL numbers only; nothing on CICIDS2017.
- **Gaps:** hybrid reasoning cost; evaluation standardisation nascent.
- **Applies to us:** 42% pass@5 validates the zero-day premise; "92% of alerts
  uninvestigated" supports P@100 over AUC; knowledge-graph verification of ML
  anomalies is an upgrade path (C's seam).

## 7. Continual learning with strategic selection and forgetting (SSF)
**Zhang et al. · arXiv:2412.16264 (2024)**

- **Method:** AE detector (AOC-IDS style — our M5a family!) + fixed memory
  buffer with strategic sample selection (drifted patterns) + strategic
  forgetting + pseudo-labels. Stream updates with **1% of new samples
  labeled**.
- **Data:** NSL-KDD, UNSW-NB15.
- **Headline:** SSF **Acc 90.50 / F1 91.90 (NSL-KDD)**, **Acc 90.27 / F1 91.40
  (UNSW-NB15)** — ~+4% over best baselines; ~90% accuracy with 0.1% labels
  (50× label reduction vs baselines needing 5%).
- **Reproduce:** Medium-high on UNSW-NB15 (local). AE detector matches M5a;
  protocol is a clean benchmark for our drift_monitor.
- **To beat:** F1 91.40 on UNSW-NB15 under their 1%-label protocol (classifier
  metrics — run identical protocol to compare).
- **Gaps:** 2 dated datasets; flow-level only (no graphs); pseudo-labels need
  a trusted detector; no CICIDS2017/2018.
- **Applies to us:** template for M6 drift handling; selective forgetting is
  the fix for gotcha #10 (attack-day "benign" half is dirty); pseudo-labels
  would refresh M5b without labels.

## 8. DRIFT-CL — MDPI Mathematics 14(14):2595 (2026)
- **Status:** NOT RETRIEVABLE. MDPI page empty, no arXiv version, DOI
  unverified. Closest verifiable source is a PhD thesis (Saidane) presenting
  DRIFT-CL + FedATA-APFL with no usable numbers.
- **Reproduce:** cannot assess. **Do not quote this paper** until full text is
  obtained (try the MDPI PDF directly or Google Scholar).
- **Gaps:** unverifiable as recorded — flag in the report as "could not be
  verified", which is itself a finding about the spreadsheet.

## 9. ReCDA — concept drift adaptation with representation enhancement
**Yang, Zheng, Li, Xu, Zhang, Ngai · IEEE TDSC 22(6):7632–7646 (2025); KDD'24**

- **Method:** self-supervised drift-aware perturbation + representation
  alignment, then weakly-supervised classifier tuning (instructive sampling).
  Binary only.
- **Data:** several benchmarks (paywalled list); neighbouring papers benchmark
  it on CIC-IDS2017/2018.
- **Headline (open source — NetGuard's 1%-label benchmark, 2017→2018):**
  ReCDA F1 72.47%, **AUROC 0.67** vs NetGuard 0.91 — i.e., weak under
  cross-network drift. ReCDA's own numbers are paywalled; do not quote.
- **Reproduce:** high (no code; tabular pipeline).
- **To beat:** AUROC 0.67 (1% labels, 2017→2018) — our M6 drift monitor is
  label-free by design, the honest comparison frame.
- **Gaps:** binary-only; feature-space perturbation criticised by SOUL
  (problem-space > feature-space); still needs labels+retraining.
- **Applies to us:** closest paper to our M6 story — the related-work anchor
  for drift. Instructive sampling = principled choice of windows for analyst
  labels (C's risk model, D's triage).

## 10. RES-DARE — failure-aware continual IDS with rollback-safe repair
**Aftab et al. · arXiv:2607.02687 (2026, preprint — check peer review status)**

- **Method:** supervised-contrastive MLP encoder + two-pass expert router +
  HDBSCAN failure-region discovery (new experts) + trust-risk monitor +
  AEHM-v2 rollback-safe self-repair (commit iff ΔF1>0 and Δrisk≤0).
- **Data:** CICIDS2017, UNSW-NB15, TON_IoT (full 4.1M samples).
- **Headline (clean):** CICIDS17 macro-F1 0.9850 / AUROC 0.9993; UNSW15 0.9736
  / 0.9972; TON 0.9691 / 0.9961. Under Gaussian corruption σ=0.10: CIC17
  Attack-F1 0.7920 / silent-failure 0.0091. Scaling drift weakness: TON@0.40
  = 0.6386 vs RF 0.9175. Static XGBoost/RF beat them on clean accuracy (honest
  paper — value is robustness).
- **Reproduce:** high (no repo). The robustness PROTOCOL (corruption strength
  vs silent-failure rate) is cheap to copy.
- **To beat:** robustness: Attack-F1 0.7920 @ σ=0.10 on CICIDS2017;
  warning AUROC ≈0.976 (our drift monitor has no published number — this
  defines the target and protocol).
- **Gaps:** scaling-drift robustness (they explicitly leave it open);
  no SHAP (they defer to it — C's opening); supervised-only (our label-free
  drift is the differentiator).
- **Applies to us:** trust-risk monitor ≈ our M6; rollback-safe repair is the
  right pattern for any future M5b auto-retraining; silent-failure rate +
  warning-AUROC protocol would give our alert pipeline a headline robustness
  number.

## 11. XAI for IDS: LIME and SHAP on MLP
**Gaspar, Silva, Silva · IEEE Access 12:30164–30175 (2024)**

- **Method:** apply LIME/SHAP to an MLP IDS over system-call sequences;
  validate explanations by perturbation (flip flagged features, check
  classification changes). Study of triage, not detection accuracy.
- **Data:** IoT system-call dataset (proprietary).
- **Headline:** qualitative: attributions help triage; FN explanations expose
  misleading features. No detection metric to beat.
- **Reproduce:** low on CICIDS2017 — apply the same protocol to M5a per-flow
  scores and M5b node scores (hours of work).
- **To beat:** the protocol itself (explanation flipping / perturbation tests)
  is the contribution to replicate and extend.
- **Gaps:** no quantitative explanation-utility measure; no graph models; no
  LIME-vs-SHAP consistency/cost comparison.
- **Applies to us:** blueprint for C's SHAP seam; "misleading features show up
  in FN explanations" maps to our feature-set analysis.

## 12. XAI-IDR — proposal/position paper
**Panchal et al. · IJCA 187(74):51–55 (2026)**

- **Method:** POSITION paper — no implementation, no code, no evaluation.
  Table 1 numbers (CIC-IDS2017 F1 0.97 / AUC 0.98) are PLANNED TARGETS, not
  measurements. Never cite them as results.
- **Applies to us:** the explain→respond loop shape matches our
  alert_pipeline + C's explainability seam. Use as: "proposals like XAI-IDR
  target MTTC −35%; we report measured P@100 instead."

## 13. UEBA in SIEM with Transformer-GNN — closest sibling
**Aljumaily, Abd, Majeed · IJMRAI 1(2):82–93 (2025)**

- **Method:** streams CERT v6.2, UNSW-NB15, TON_IoT as Kafka logs into an
  ELK-emulated SIEM; benchmarks LSTM-AE / Transformer (LogBERT) / GNN
  (HeteroGraph, 3 GCN layers); **60-second batch inference windows** (same as
  our design!), weighted-voting alert fusion, role-aware prioritisation, SHAP,
  analyst feedback.
- **Headline (per-dataset F1 ± 95% CI):** LSTM 0.86/0.81/0.79; Transformer
  0.90/0.88/0.86; **GNN 0.91/0.89/0.88**; **ensemble 0.93/0.91/0.90**
  (CERT/UNSW-NB15/TON_IoT). Ensemble +7% F1 vs standalone; triage 18min→<4min.
  Domain shift CERT→UNSW: GNN precision 0.94→0.84. No seeds reported.
- **Reproduce:** low-medium on UNSW-NB15 (local, cleanest) — run our M5b on
  UNSW and compare per-dataset F1.
- **To beat:** **GNN F1 0.89 ± 0.02 on UNSW-NB15** — the one directly
  comparable cell; and ensemble 0.93/0.91/0.90.
- **Gaps:** no concept drift (they list it as FUTURE WORK — that's literally
  our M6); no seeds; aggregated results hide per-family behaviour; no
  per-attack-family numbers; no zero-day withholding protocol.
- **Applies to us:** 60s windows independently confirmed (their LSTM-AE vs GNN
  comparison mirrors our M5b temporal-vs-graph ablation — they see a
  difference where we measured +0.0005; the tasks differ: behaviour logs vs
  flow windows — worth a paragraph in the report); role-aware weighting is a
  plug-in for C's risk model.

## 14. Explainable UEBA with deep autoencoders — closest architectural analogue
**Fuentes, Ortega-Fernandez, Villanueva, Sestelo · AIMS Mathematics 10(10):23496 (2025)**

- **Method:** host-level deep AE [64,32,16,8,16,32,64] over 19 numeric
  behaviour features + 64-d Doc2Vec embeddings (83 inputs); threshold = 95th
  percentile of validation reconstruction error; explainability via per-feature
  log reconstruction-error residuals.
- **Data:** proprietary financial-institution logs (1 year), UNLABELLED.
- **Headline:** NO precision/recall/F1/AUC at all — only calibrated output
  rates (5.09% / 4.61%) and synthetic-anomaly detection (λ>0.7).
- **Reproduce:** high (proprietary data, no code) — but their METHOD is our
  M5b baseline already.
- **To beat:** none (no supervised metric exists in the paper). Frame
  honestly: "the only published host-level deep-AE UEBA uses unlabelled
  proprietary data and reports no detection metrics; we report AUC and P@100
  on public benchmarks."
- **Gaps:** no public data/code/baselines; no supervised evaluation (ours is a
  strict superset); Doc2Vec obscures rare tokens; explainability never
  quantitatively validated (C's SHAP fills this hole).
- **Applies to us:** strongest related-work citation for the host-graph AE
  design; 95th-percentile threshold calibration is a concrete fix proposal for
  gotcha #7 (uncalibrated DEFAULT_THRESHOLD); per-feature residual
  explanations = blueprint for C's seam; their 19 numeric features support our
  feature-set v2 direction.

## 15. Deep-learning UBA — review
**Akampurira, Edozie, Sadiq, Buhari · F1000Research 15:674 (2026)**

- **Method:** PRISMA review, 159 studies (2010–2025). Narrative synthesis.
  Reviewer-approved with reservations.
- **Headline (cited ceilings):** AE+VAE insider threat: 91% accuracy / AUC
  0.94 (CERT); BRITD Bi-LSTM+FNN AUC 0.9730; RNN 98.94% on consecutive
  attacks. Their thesis: accuracy-centric paradigm is wrong for open-world
  detection; attention ≠ confidence.
- **Reproduce:** N/A (review).
- **To beat:** cited ceilings on CERT-style data: AUC 0.94 (AE+VAE), 0.9730
  (BRITD) — chase originals before quoting.
- **Gaps they name (claimable):** risk-confidence co-estimation; uniform
  thresholds across heterogeneous users (wrong); deep models are
  "epistemically blind" under drift (our M6).
- **Applies to us:** independent support for AE/VAE framing, LSTM temporal
  half, ensemble fusion, context-aware alerting; our reconstruction error is
  an uncertainty signal by construction — say that; ISO/IEC 27001:2022 +
  Zero Trust discussion is free material for the compliance section.

---

## Cross-paper comparability warnings (read before quoting anything)

1. **Deep PackGen** — packet-level classifier ASR; orthogonal to our AUC/P@100.
2. **Venturi et al.** — DR at fixed injection budget β on CTU-13/ToN-IoT;
   re-run as AUC-drop under injection on CICIDS2017 to make comparable.
3. **MDPI SLR** — pooled AUC 0.94 is third-party summarized, unverified.
4. **Always be Pre-Training** — micro-F1, undirected, subsampled; F1 ≠ ROC-AUC.
5. **Wang et al. (GIDS)** — AUC/AP/TPR/FPR on CIC-IDS-2017: the most comparable
   external numbers (PIKACHU 0.977); verify their graph construction first.
6. **Neuro-Symbolic** — survey-synthesised; LANL anchors only.
7. **SSF** — accuracy/F1 classifier protocol on NSL-KDD/UNSW-NB15; replicate
   the protocol if we adopt the track.
8. **DRIFT-CL** — no verifiable numbers at all.
9. **ReCDA** — own numbers paywalled; only third-party benchmark (AUROC 0.67
   at 1% labels) is open.
10. **RES-DARE** — supervised classifier F1; our AE premise is the
    differentiator, not a rival.
11. **IEEE Access XAI** — no detection metric; the protocol is the contribution.
12. **XAI-IDR** — planned targets, not measurements; never cite as results.
13. **IJMRAI** — main table aggregates 3 datasets; per-dataset F1 only in the
    CI table; preprint check.
14. **AIMS** — no supervised metric exists.
15. **F1000** — review; chase original studies for any number.

**Directly quotable external benchmarks for the FYP:**
- PIKACHU **AUC 0.977 / AP 0.872** on CIC-IDS-2017 (Wang et al.) — the bar.
- KnowGraph inductive AUC 0.9112 on LANL (neuro-symbolic survey).
- GNN F1 0.89±0.02 on UNSW-NB15 (IJMRAI) — per-dataset, same metric family.
- Edge-injection: C2x with K∈{2,5} defeats 3 SOTA GIDS on LANL (Venturi,
  Wang) — our red-team recipe.

---

# Batch 2 � web searches 2026-08-13 (16 papers, coverage to 2026-08-10)

Same legend. These were found via live web search, not the Excel sheet. Most are
supervised CLASSIFIERS posting 99%+ on CICIDS2017 � useful as bars and as
sources of transferable machinery, but they measure closed-set classification,
not zero-day detection. Flagged per paper.

## 16. AutoGraphAD � heterogeneous VGAE, the closest thing to a direct competitor
**Anyfantis & Barlet-Ros (UPC � the Anomal-E/BNN-UPC group) � arXiv:2511.17113v3, 2026-07-10 � IEEE NetSoft 2026, pp. 255-260**

- **Method:** unsupervised heterogeneous VGAE: IP nodes (placeholders) +
  CONNECTION nodes (flow features); GraphSAGE enc/dec; GraphMAE-style node
  masking, random edge drop, negative edge sampling (contrastive); feature
  recon (MSE or cosine) + STRUCTURE recon (learnable-weighted dot product,
  BCE) + KL, combined with tuned weights; robust-scaled; percentile threshold
  chosen offline with labels.
- **Data:** UNSW-NB15 only, NFStream NetFlow V9 features, 180s non-overlapping
  windows, undirected graphs. Contamination levels 0 / 3.36 / 5.76%.
- **Headline (0% contamination):** Accuracy 97.69%, **F1 macro 84.23%**, recall
  macro 87.98%. Anomal-E PCA: 96.65/82.39/98.27. No AUC/AP anywhere.
  Inference 0.0099 s/pass vs Anomal-E estimators 0.029-0.087 s.
- **Reproduce:** Medium on UNSW-NB15 (they publish code, github.com/georgeani/
  AutoGraphAD). The masking+edge-drop+structure-recon recipe is portable to
  our host graphs.
- **To beat:** F1 macro 0.8423 on UNSW-NB15 (their metric, their dataset �
  our UNSW transfer run measures ROC-AUC, different axis; add F1 macro to the
  transfer eval to make it comparable).
- **Gaps we can claim:** they evaluate ONE dataset; our held-out-family
  protocol + IDS2018 cross-network transfer is strictly stronger evidence.
  Their threshold needs labels at selection time (they admit score-weight
  selection uses labels); ours is label-free at every step. No drift monitor,
  no adversarial eval, no edge-level alerting, no ensemble, 100-epoch
  max-fixed training vs our seed-ensembled checkpoints.
- **Applies to us:** (a) structure reconstruction loss (predict edge
  existence from embeddings) � a cheap second anomaly signal per edge,
  adjacent to our EdgeAutoencoder; (b) masking/edge-drop as AE regularisers
  are untested on our 8-feature host graphs and are the natural E4-adjacent
  experiment if similarity edges do not move AUC; (c) robust scaling of loss
  components = our per-member percentile calibration, same idea.
- **July 2026 note:** v3 revised 2026-07-10 � the version to cite.

## 17. GAT-AID � dual branch: known-attack classifier + zero-day AE
**Wankhade & Khandare � ISeCure 18(2), July 2026**

- **Method:** GAT over flow graphs -> embeddings -> dual branch: MLP classifier
  (known attacks) + AE anomaly detector (zero-day). GAT for relational context.
- **Data:** CICIDS2017 + UNSW-NB15.
- **Headline:** beats SVM/RF/CNN/GCN baselines; no exact numbers in abstract
  (paywalled details).
- **Applies to us:** independent validation of the two-headed idea our M5a+M5b
  fusion implements; their AE branch is our M5b in spirit. Note: their
  classifier branch needs labels for known families � ours needs none.

## 18. DMSTG-AD � dynamic multi-scale spatio-temporal GNN
**Scientific Reports, 2026-03-22**

- **Method:** GRU-driven dynamic node embeddings, adaptive adjacency, edge-node
  collaborative convolution, multi-scale dilated conv + BiGRU, spatio-temporal
  cross-attention (STCA) fusion.
- **Data:** CIC-IDS2017 (99.34% acc), InSDN (99.88%).
- **Headline:** ablation: removing temporal module -1.38pts, removing STCA
  fusion -3.22pts (CICIDS2017 acc).
- **Applies to us:** their adaptive-adjacency idea is similarity/KNN edges
  (our E4). The "edge-node collaborative convolution" = message passing that
  consumes edge features � our SAGEConv ignores edge_attr; the edge AE is the
  workaround. Supervised classifier; comparability limited to transfer of
  mechanisms, not numbers.

## 19. HybridSAGETransformerGlobal � SAGEConv + Transformer encoder
**Electronics 15(8):1737, 2026-04-20**

- **Method:** flows as NODES; edges = IP-group-aware KNN + temporal chain;
  gated fusion, positional encodings, class weighting, label smoothing;
  5-seed repeated runs (the discipline we already follow).
- **Data:** UNSW-NB15 (acc 0.9841�0.0006, macro-F1 0.9749�0.0011), CIC-IDS2017
  (acc 0.9749, macro-F1 0.9613, **ROC-AUC 0.9957**).
- **Applies to us:** KNN-similarity auxiliary edges is the same structural fix
  as our E4; their ROC-AUC 0.9957 is a supervised bar on CICIDS2017 � not
  comparable to our unsupervised edge-level AUC, but the number reviewers
  will have seen.

## 20. QIHHO-GTrNIDS � quantum-inspired optimizer + graph transformer
**Scientific Reports, 2026-08-10 (the newest dated paper found)**

- **Method:** quantum-encoded horse-herding optimizer for feature subset
  selection; GNN encoder + transformer decoder; low FAR design.
- **Data:** NSL-KDD 98.42%, UNSW-NB15 99.03%, CICIDS2017 **99.12% acc, FAR
  0.0091**.
- **Applies to us:** feature selection angle maps to our feature engineering;
  numbers are classifier-accuracy on CICIDS2017 (saturated axis).

## 21. ST-GAT-Fusion � GAT + TCN with dynamic graph reconstruction
**Discover Computing 29:114, 2026-02-23**

- **Method:** 2s windows / 1s stride; Top-K similarity-driven adjacency in
  ADDITION to physical connectivity; GAT + TCN; leave-one-out zero-day eval
  (+15.4% over CNN/LSTM on zero-day).
- **Data:** CIC-IDS2017 (acc 99.96%, FPR 0.04%), UNSW-NB15 (F1 99.76%).
- **Applies to us:** SECOND independent source for similarity/KNN auxiliary
  edges (supports E4); their leave-one-out zero-day protocol is our
  held-out-family protocol � good precedent to cite. Note their zero-day
  claim is still per-family-supervised training; ours trains on benign only.

## 22. RF-PGNN � Random Forest + GAT ensemble
**Das, Chandrakala, Nathasha � BJSS 15(4):98-110, 2026**

- **Method:** RF leaf-assignment proximity graph -> GAT; weighted ensemble
  (RF 0.9 / GAT 0.1).
- **Data:** balanced 7-class CIC-IDS2017 subset: RF alone 98.86 acc, GAT alone
  78.34, ensemble 98.94 acc / macro-F1 0.9894 / **ROC-AUC 0.9986**.
- **Applies to us:** the ensemble lesson � a weak relational detector adds a
  consistent but small boost; over-weighting it hurts. Mirrors our
  M5b-alone-beats-fusion finding. Their GAT alone being terrible (78%) while
  the ensemble gains is a citation-grade argument against classifier-GNN
  single models.

## 23. GCN-DQN � GCN + attention + deep Q-networks
**Sensors 26(5):1421, 2026-02-24**

- **Method:** RL (DQN) adjusts attention weights; SHAP/LIME explainability.
- **Data:** CICIDS2017 99.02% acc, UNSW-NB15 97% (binary).
- **Applies to us:** reinforcement-learned attention is overkill for our
  scale; the explainability section is C's territory (SHAP seam exists).

## 24. Robust GNN DDoS detection � adversarial training + proximal optimization
**Chatterjee � Social Network Analysis and Mining 16:39, 2026-02-14**

- **Method:** dynamic graph (nodes=IPs, edges=flows � OUR representation),
  min-max adversarial training, proximal gradient stabilization.
- **Data:** CIC-IDS2017 + BoT-IoT: **F1 94.7%**, robust acc 87.9% under PGD
  attack.
- **Applies to us:** the ONLY recent work found with our exact representation;
  adversarial training for AEs (not classifiers) is still open � our red-team
  harness quantifies the AE version of this claim.

## 25. Semantic-guided edge enhancement � node-edge-node attention, SSL
**Zhang et al. � Scientific Reports, 2026-07-04**

- **Method:** edge-aware attention + intra-edge self-attention; semantic-aware
  contrastive learning; 7 SOTA baselines, 4 datasets.
- **Applies to us:** the edge-is-a-first-class-citizen theme (our edge AE +
  rank_mean edge scoring already implements it in AE form); contrastive
  learning on OUR pipeline would be a full redesign, deprioritised.

## 26. SKGFusionKAN � edge-oriented GraphSAGE + selective kernel + KAN
**Zhao, Ji, Cheng, He � arXiv:2607.02981, 2026-07-03**

- **Method:** multi-scale selective-kernel attention on edges, gated fusion,
  KAN classifier. IoT-targeted.
- **Data:** 4 IoT benchmarks.
- **Applies to us:** same edge-centric theme; IoT datasets not in our stack;
  KAN replaces the classifier stage we deliberately don't have.

## 27. SSGMHAN � self-supervised GNN multi-head attention, cloud-edge
**Journal of Cloud Computing 15:29, 2026-01-31**

- **Method:** structure-aware graph contrastive learning (GSC), multi-head
  node-edge attention, dynamic edge pruning.
- **Data:** 3 NetFlow benchmarks; beats unsupervised SOTA.
- **Applies to us:** contrastive pretraining alternative to plain AE loss;
  edge pruning maps to our alert-threshold idea. Deprioritised (redesign).

## 28. Adaptive temporal GNN � multi-stage enterprise attacks
**Suharsono, Kurniawan, Dewi et al. � Discover Computing 29:455, 2026-07-21**

- **Method:** dynamic interaction graphs + temporal attention; host/auth event
  graphs (LANL, DARPA TC), NOT network flows.
- **Headline:** +5% acc over GAT; noise-robust; attack-path explainability.
- **Applies to us:** temporal attention validates our E3 persistence axis
  (cross-window consistency); their event-graph domain is Pillar 3-adjacent.
  Not a flow-level bar.

## 29. GraphIDS � GNN + transformer masked autoencoder
**Guerra, Chapuis, Duc, Mozharovskyi, Nguyen � OpenReview (arXiv:2509.16625)**

- **Method:** inductive E-GraphSAGE embeds each FLOW with local topological
  context; transformer encoder-decoder reconstructs embeddings; high recon
  error = anomaly. End-to-end self-supervised.
- **Data:** NetFlow benchmarks: up to 99.98% PR-AUC, 99.61% macro F1.
- **Applies to us:** masked-AE design (GraphMAE lineage, same family as
  AutoGraphAD); flow-as-node representation differs from our host-node
  design; the PR-AUC axis is worth adopting as a metric.

## 30. RLD/FPC � detecting PANDA-style evasion of AE-based NIDS
**Bunzel & Siwakoti � arXiv:2607.01194, 2026-07-01**

- **Method:** PANDA attacks CNN-AE NIDS via invertible packet->image maps +
  masked FGSM on inter-arrival times. Two defence detectors: RLD (residual
  localisation in image space) and FPC (perturbation consistency in feature
  space); both F1>=0.99 vs adversarial traffic on UQ-IoT.
- **Applies to us:** PANDA is the packet-level analogue of our D-red-team;
  M5a (per-flow AE) is exactly the PANDA attack surface. Their RLD/FPC
  detectors are a defence pattern our M6 drift monitor could absorb (score
  consistency vs perturbation). IoT-only data, preprint, 0 citations.

## 31. BNN-UPC GNN-NIDS (2021, still the robustness anchor)
**Pujol-Perich, Su�rez-Varela, Cabellos-Aparicio, Barlet-Ros � arXiv:2107.14756**

- **Method:** flows-as-nodes GNN; robustness to packet-size / inter-arrival
  perturbations: their GNN keeps accuracy while ML baselines degrade up to 50%
  F1. Code on GitHub.
- **Applies to us:** the citation-grade claim "GNN structure survives the
  perturbations that gut flow classifiers" � our red-team harness should
  reproduce this exact experiment shape on M5a vs M5b (they only attacked
  supervised classifiers; AE version is open).

## Updated comparability warnings (batch 2)

- Most batch-2 papers are supervised classifiers on CICIDS2017 with
  near-saturated accuracy (99%+); they measure closed-set classification.
  Quote them as "the supervised bar", never as rivals on zero-day detection.
- **AutoGraphAD is the only direct unsupervised competitor** (VGAE, F1 macro
  0.8423 on UNSW-NB15, no AUC). Beating it needs the UNSW-NB15 transfer arm
  re-scored on F1 macro.
- HybridSAGE ROC-AUC 0.9957 and RF-PGNN AUC 0.9986 on CICIDS2017 are
  supervised bars; our honest comparable is the node-level 0.9300 family
  protocol or edge-level production numbers, stated as such.

**Directly quotable batch-2 bars:**
- AutoGraphAD F1 macro 0.8423 / acc 0.9769 on UNSW-NB15 (unsupervised).
- HybridSAGE macro-F1 0.9749�0.0011 UNSW-NB15 / ROC-AUC 0.9957 CICIDS2017 (sup.).
- Robust GNN-DDoS F1 0.947 / PGD-robust acc 0.879 (sup.).
- ST-GAT-Fusion zero-day +15.4% over CNN/LSTM, leave-one-out protocol.
- RLD/FPC defence F1 >= 0.99 vs PANDA (AE attack surface).
