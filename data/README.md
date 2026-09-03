# `data/` — what is what

> **Gitignored** (`/.gitignore` → `/data/`). Each machine fetches its own copy.
> Never commit CSVs/binetflows — they are gigabytes and gated behind registration.
> `data/README.md` is the only file that ships.

---

## A) TRAINING data — what `detection/` actually learns from

```text
data/GeneratedLabelledFlows/TrafficLabelling/
└── Monday-WorkingHours.pcap_ISCX.csv   ← THE ONLY file used to train
    (529,918 flows, 487×60s + 98×300s benign graphs, 200ep, seed 0)
    → produces: detection/gnn_autoencoder_v1_logscale.pt       (8/19 dims)
               detection/gnn_autoencoder_v1_logscale_v2.pt     (19 dims)
               detection/m5a_revived_ctx.pt                    (87 dims, flow)
```

* Every held-out evaluation (Tuesday–Friday attack days) treats that day's
  traffic as **unseen** — zero-day by construction.
* MachineLearningCSV Monday is **also train-capable** (same benign pool,
  different 79-col layout), but the official pipeline uses the
  GeneratedLabelledFlows 85-col release (has IP columns, latin-1, see
  `graph_builder.read_flows()`).

---

## B) HELD-OUT test families — train never sees them

```text
data/GeneratedLabelledFlows/TrafficLabelling/
├── Tuesday-WorkingHours.pcap_ISCX.csv                          → Patator (FTP/SSH)
├── Wednesday-workingHours.pcap_ISCX.csv                        → DoS / Heartbleed
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv      → WebAttacks
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv → Infiltration
├── Friday-WorkingHours-Morning.pcap_ISCX.csv                   → Botnet
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv        → PortScan
└── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv            → DDoS
```
*Each file = one row in the ablation table (`eval_mw_ablation_4seed.py`).*

---

## C) EXTERNAL replication — a different lab / decade / capture stack

```text
data/CSE-CIC-IDS2018/
└── Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv  ← the only 2018 file with IPs
    (10 files exist; the other nine have no IP columns.  Typo is official.)

data/CTU-13/
├── ctu13_s1_neris.binetflow
├── ctu13_s13_virut.binetflow
└── ctu13_s3_rbot.binetflow                               ← real Stratosphere botnets
```

* Protocol: train on the benign slice **before the first attack timestamp**, evaluate the rest.
* IDS2018: `eval_external_ids2018.py` → `external_ids2018_multiseed.json`
* CTU-13  : `eval_external_ctu13.py`  → `external_ctu13_multiseed.json`

---

## D) RESULTS / run-the-model outputs (never data)

*Everything below is a **number**, not a CSV.*

| Artefact | produced by | what it contains |
|---|---|---|
| `experiments/mw_ablation_4seed.json` | `eval_mw_ablation_4seed.py` | 7-family AUC band, 4 seeds |
| `experiments/feature_set_v2_results.json` | `eval_feature_set_v2.py` | 19-feat ablation |
| `experiments/baselines_4seed.json` | `eval_baselines_4seed.py` | PCA/IF/MLP-AE vs GNN |
| `experiments/external_ids2018_multiseed.json` | `eval_external_ids2018.py` | IDS2018 ranks, 4 seeds |
| `experiments/external_ctu13_multiseed.json` | `eval_external_ctu13.py` | CTU-13 ranks, 4 seeds |
| `detection/training_features/README.md` | frozen spec | 87-dim flow + 19-dim graph feature lists |
| `schemas/feature_vector.json:3.0` | frozen spec | same lists, machine-readable |

**To run the headset result end-to-end (one command, host-level headline):**

```powershell
python detection/eval_mw_ablation_4seed.py --seeds 0 1 2 3 --epochs 60
```

---

## E) What used to be here

* `training_data/` is gone. `training_data/dataset_10k_normal.csv` and
  `live_capture.csv` were synthetic 76-col captures (collapsed / port-counter
  artefacts — `graph_health()` flagged them). Kept only for Checkpoint-1 demos;
  removed 2026-08-25 to unconfuse the pipeline. Generate a fresh 87-dim demo
  from Monday if you need one.
