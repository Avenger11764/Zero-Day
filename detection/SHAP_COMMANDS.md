# SHAP Explainer — Command Reference

**Script:** `detection/shap_revived_ctx.py`  
**Model:** `detection/m5a_revived_ctx.pt` (87-dim autoencoder: 76 flow features + 11 context dims)  
**Interpreter:** `/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python`

> **All commands are run from the project root:**
> `cd /home/dell/Documents/Coding/7Project_finalYear/Zero-Day`

---

## Host-AE SHAP interface (Week 5)

`detection/host_shap_explainer.py` exposes `explain_host_anomaly()` for a
reconstruction autoencoder and model-ready host vectors. Pass a benign
background matrix and feature names matching the model's exact training
representation. The canonical 128-D handover uses
`HostFeatureExtractor.FEATURE_NAMES`; legacy V+3 checkpoints can derive names
from checkpoint vocabulary with `feature_names_from_checkpoint()`.

The checked-in `host_autoencoder_adfa.pt` currently expects 153 inputs, not
the handover's 128-D vector. Do not pair it with the 128-D names or claim a
host SHAP result until B supplies a compatible checkpoint and host traces.
Returned attributions omit raw feature values for the Week 6 alert privacy
contract.

## Quick Reference — All Flags

| Flag | Default | What it controls |
|------|---------|-----------------|
| `--csv PATH` | `training_data/Monday-WorkingHours.pcap_ISCX.csv` | Input flow CSV (labelled or unlabelled) |
| `--model PATH` | `detection/m5a_revived_ctx.pt` | Checkpoint to explain |
| `--n-flows N` | `1` | How many flows to explain (`0` = all) |
| `--top-k N` | `10` | Features shown per flow in console + JSON |
| `--n-bg N` | `100` | Background samples for DeepExplainer |
| `--all-labels` | off | Explain ALL rows (bypasses default BENIGN filter) |
| `--label NAME` | _(none)_ | Filter CSV rows by label substring for testing (e.g. `PortScan`, `Web`, `DDoS`) |
| `--shuffle` | off | Randomly sample rows from CSV before picking `--n-flows` |
| `--mapper PATH` | _(auto)_ | Path to network attack mapper JSON (e.g. `attack_mappers/network_attack_mapper.json`) |
| `--threshold T` | `0.005` | Anomaly score threshold for BENIGN vs ANOMALOUS verdict |
| `--window N` | `60` | Time-window bucket size in seconds (must match training) |
| `--out-json PATH` | _(none)_ | Save full results as JSON |
| `--out-csv PATH` | _(none)_ | Save SHAP value matrix as CSV |
| `--plot-bar` | off | Save a bar chart PNG per explained flow |
| `--plot-beeswarm` | off | Save a global beeswarm summary PNG |
| `--seed N` | `0` | RNG seed for background sampling |
| `--verbose` | off | Show DEBUG log messages |

---

## 0 — Real-World Deployment: Unlabelled Live Traffic CSV

> **In real-world deployment, network traffic flows do NOT have labels.**  
> The script processes raw numerical features, computes reconstruction MSE scores, and classifies attack families using SHAP attributions and `attack_mappers/network_attack_mapper.json` without needing any label column!

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv path/to/unlabelled_live_traffic.csv \
  --all-labels --shuffle \
  --n-flows 50 \
  --top-k 10 \
  --threshold 0.001
```

**What happens:**
1. Loads the unlabelled CSV file directly (populates `label='UNLABELLED'` automatically if no label column exists).
2. Randomly shuffles and samples 50 flows.
3. Passes features to `m5a_revived_ctx.pt` to compute raw MSE scores.
4. Uses `DeepExplainer` to calculate exact mathematical SHAP attributions per feature.
5. Matches top positive SHAP features against network profiles in `attack_mappers/network_attack_mapper.json` to produce MITRE ATT&CK verdicts (`PortScan`, `DDoS`, `Patator`, `Web Attack`, `Exfiltration`, etc.) or `BENIGN`.

---

## 1 — Minimal: explain 1 flow, print to console

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py
```

**What you get:**
- Anomaly score for the first benign flow in the default CSV
- Top 10 features ranked by |SHAP|, with sign and scaled value
- Nothing saved to disk

---

## 2 — Explain 1 flow from a specific CSV

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv data/GeneratedLabelledFlows/TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv
```

**What you get:**
- Same as above but reads from the path you provide
- Path is resolved automatically: tries as-given → `ROOT/path` → `training_data/<name>`
- Safe to pass any variant of the CICIDS2017 path

---

## 3 — Explain N flows, show top-K features each

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 50 \
  --top-k 10
```

**What you get:**
- SHAP attribution table for flows 0–49 printed to stdout
- Each row: `Rank | Feature | SHAP value | Scaled input value | Direction`
- `↑ anomaly` = this feature is *pushing the score up* (unusual value)
- `↓ anomaly` = this feature is *pulling the score down* (normal/benign value)

---

## 4 — Explain all flows in the CSV

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 0 \
  --top-k 10
```

**What you get:**
- Full SHAP pass over every BENIGN row in the CSV
- ⚠️ Can be slow for large files (Monday CSV ~77k rows); use `--n-flows` to limit

---

## 5 — Save results to JSON (structured output)

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 50 \
  --top-k 10 \
  --out-json shap_out.json
```

**What you get:**
- `shap_out.json` — list of objects, one per flow:
  ```json
  [
    {
      "flow_idx": 0,
      "anomaly_score": 0.000512,
      "top_features": [
        { "rank": 1, "feature": "fwd_blk_rate_avg", "shap_value": -0.004762,
          "input_scaled": 1.0, "direction": "↓ anomaly" },
        ...
      ]
    }
  ]
  ```
- Useful for feeding results into the dashboard or further analysis

---

## 6 — Save SHAP value matrix to CSV

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 200 \
  --out-csv shap_matrix.csv
```

**What you get:**
- `shap_matrix.csv` — shape `(N_flows × 87)`, columns = all 87 feature names
- Each cell = the SHAP value for that feature in that flow
- Good for statistical analysis (e.g., mean |SHAP| per feature across all flows)

---

## 7 — Bar chart plots (one PNG per flow)

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 10 \
  --top-k 15 \
  --plot-bar
```

**What you get:**
- `shap_bar_flow0.png` … `shap_bar_flow9.png`
- Each PNG: horizontal bar chart, top-15 features by |SHAP|
- Red bars = feature pushes anomaly score **up** (suspicious)
- Blue bars = feature pulls anomaly score **down** (normal)
- Good for: thesis figures, per-alert explanations in the dashboard

---

## 8 — Beeswarm summary plot (all flows in one chart)

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 200 \
  --top-k 20 \
  --plot-beeswarm
```

**What you get:**
- `shap_beeswarm.png` — global SHAP summary across all 200 flows
- Each dot = one flow; colour = feature value (low→blue, high→red)
- x-axis = SHAP value (impact on anomaly score)
- Features sorted by mean |SHAP| — most impactful at the top
- Best chart for the thesis/report to show which features matter most globally

---

## 9 — Full output: JSON + CSV + both plots (project demo / thesis run)

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv data/GeneratedLabelledFlows/TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 50 \
  --top-k 10 \
  --out-json shap_out.json \
  --out-csv shap_matrix.csv \
  --plot-bar \
  --plot-beeswarm
```

**What you get:**
- Console: per-flow attribution table
- `shap_out.json` — structured JSON results
- `shap_matrix.csv` — raw SHAP value matrix
- `shap_bar_flow{i}.png` × 50 — individual bar charts
- `shap_beeswarm.png` — global summary

---

## 10 — Larger background for more stable SHAP values

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 50 \
  --n-bg 300 \
  --top-k 10
```

**What you get:**
- Same output as variant 3, but DeepExplainer uses 300 background samples
- More stable/reliable SHAP values (lower variance between runs)
- Slightly slower than default `--n-bg 100`
- Recommended for final report figures

---

## 11 — KernelExplainer fallback (model-agnostic, slow)

```bash
/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python detection/shap_revived_ctx.py \
  --csv training_data/Monday-WorkingHours.pcap_ISCX.csv \
  --n-flows 5 \
  --kernel \
  --nsamples 100 \
  --top-k 10
```

**What you get:**
- Same attribution table, but computed via KernelExplainer (perturbation-based)
- Much slower: ~100 forward passes per flow vs. one gradient pass with DeepExplainer
- Use for: sanity-checking DeepExplainer results, or when gradient flow is unavailable
- `--nsamples` controls the perturbation budget (higher = more accurate but slower)

---

## 12 — Import API (use inside another Python script)

```python
import sys
sys.path.insert(0, "/home/dell/Documents/Coding/7Project_finalYear/Zero-Day")

from detection.shap_revived_ctx import load_checkpoint, explain_batch, top_k_table
from detection.graph_builder import normalize_columns, read_flows

ckpt = load_checkpoint()                          # loads m5a_revived_ctx.pt
df   = normalize_columns(read_flows("training_data/Monday-WorkingHours.pcap_ISCX.csv"))
df   = df[df["label"].str.upper() == "BENIGN"].head(20)

shap_values, scores = explain_batch(df, ckpt, n_bg=100)

table = top_k_table(shap_values, scores,
                    x87=...,   # build with _build_x87 if needed
                    k=10)

for entry in table:
    print(entry["anomaly_score"], entry["top_features"][0])
```

**What you get:**
- `shap_values` — `np.ndarray` shape `(N, 87)`
- `scores`      — `np.ndarray` shape `(N,)` — raw MSE anomaly score
- `table`       — list of dicts ready to serialise to JSON or render in dashboard

---

## Output Files Summary

| File | Created by flag | Contents |
|------|----------------|----------|
| `shap_out.json` | `--out-json` | Per-flow attribution table (score + top-k features) |
| `shap_matrix.csv` | `--out-csv` | Full 87-dim SHAP value matrix |
| `shap_bar_flow{i}.png` | `--plot-bar` | Bar chart per flow (top-k features, red/blue) |
| `shap_beeswarm.png` | `--plot-beeswarm` | Global beeswarm summary across all flows |

---

## Reading the Console Output

```
Flow    0  anomaly_score=0.000512
  Rank  Feature                        SHAP        Scaled val  Direction
  ----  -----------------------------  ----------  ----------  --------------
  1     fwd_blk_rate_avg              -0.004762    1.0000      ↓ anomaly
  2     fwd_iat_min                   -0.004514    0.9976      ↓ anomaly
  5     fwd_iat_std                   +0.000382    0.6667      ↑ anomaly
```

| Column | Meaning |
|--------|---------|
| `anomaly_score` | Raw MSE reconstruction error (higher = more anomalous) |
| `Feature` | One of the 87 model input features (76 flow + 11 context) |
| `SHAP` | How much this feature contributed to the anomaly score relative to the benign baseline. Positive = increases score (suspicious), negative = decreases score (normal). |
| `Scaled val` | The feature's value after MinMax scaling to [0, 1] |
| `Direction` | `↑ anomaly` = pushing score up; `↓ anomaly` = pulling score down |


## Labels 
Ran command: `/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python - << 'EOF'
from pathlib import Path
import pandas as pd

p = Path("training_data/TrafficLabelling")
all_labels = set()
by_file = {}

for c in sorted(p.glob("*.csv")):
    # read chunk or label column
    df = pd.read_csv(c, usecols=lambda col: col.strip().lower() == 'label', nrows=500000)
    col = [col for col in df.columns if col.strip().lower() == 'label'][0]
    unique_l = df[col].astype(str).str.strip().unique().tolist()
    by_file[c.name] = unique_l
    for l in unique_l:
        all_labels.add(l)

print("Unique labels across all CSVs:")
for l in sorted(all_labels):
    print(" -", repr(l))

print("\nPer File Breakdown:")
for f, lbls in by_file.items():
    print(f"\n{f}:")
    for l in lbls:
        print("  *", repr(l))
EOF`

Notice the `UnicodeDecodeError` on byte 0x96 (`\x96`) in `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`!
Let's pass `encoding='cp1252'` or `encoding='latin1'` to read all CSV labels cleanly.

Let's test in Python with `encoding='latin1'`.

Ran command: `/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python - << 'EOF'
from pathlib import Path
import pandas as pd

p = Path("training_data/TrafficLabelling")
all_labels = set()
by_file = {}

for c in sorted(p.glob("*.csv")):
    df = pd.read_csv(c, encoding="latin1", nrows=1000000)
    col = [col for col in df.columns if col.strip().lower() == 'label'][0]
    unique_l = df[col].astype(str).str.strip().unique().tolist()
    by_file[c.name] = unique_l
    for l in unique_l:
        all_labels.add(l)

print("=== ALL UNIQUE DATASET LABELS ===")
for l in sorted(all_labels):
    print(" -", l)

print("\n=== LABELS PER DATASET FILE ===")
for f, lbls in by_file.items():
    print(f"\n📁 {f}")
    for l in lbls:
        print("   •", l)
EOF`

Let's get status of command.

Let's convert `df[col]` to string explicitly so `nan` or numbers don't trigger float/str comparison error!

Let's run a quick python snippet to print the labels.

Ran command: `/home/dell/Documents/Coding/7Project_finalYear/.zeroD/bin/python - << 'EOF'
from pathlib import Path
import pandas as pd

p = Path("training_data/TrafficLabelling")
all_labels = set()
by_file = {}

for c in sorted(p.glob("*.csv")):
    df = pd.read_csv(c, encoding="latin1", low_memory=False)
    col = [col for col in df.columns if col.strip().lower() == 'label'][0]
    unique_l = [str(x).strip() for x in df[col].dropna().unique()]
    by_file[c.name] = unique_l
    for l in unique_l:
        if l and l.upper() != 'LABEL':
            all_labels.add(l)

print("=== ALL UNIQUE DATASET LABELS ===")
for l in sorted(all_labels):
    print(" -", l)

print("\n=== LABELS PER DATASET FILE ===")
for f, lbls in by_file.items():
    clean_lbls = [l for l in lbls if l and l.upper() != 'LABEL']
    print(f"\nFILE: {f}")
    for l in clean_lbls:
        print("   -", l)
EOF`

Let's get status of command.

That output is completely clean and accurate!
Let's organize the response clearly:

1. **Complete List of All 15 Unique Ground-Truth Labels** in the CICIDS2017 dataset.
2. **Breakdown of Labels per Dataset File** (8 CSV files).
3. How to use `--label <name>` with any of these substrings.

Let's present this clearly to the user.Here is the complete list of all **15 unique ground-truth attack & baseline labels** present across the CICIDS2017 dataset, along with their breakdown per dataset file:

---

### Complete Master Label List (15 Unique Labels)

1. `BENIGN` — Normal baseline network traffic
2. `Bot` — Botnet / C2 Automated Beaconing
3. `DDoS` — Distributed Denial of Service (LOIC Flood)
4. `DoS GoldenEye` — DoS HTTP Resource Exhaustion
5. `DoS Hulk` — DoS High Volume Request Flood
6. `DoS Slowhttptest` — DoS Slow Read/Header Exhaustion
7. `DoS slowloris` — DoS Slow Header Connection Exhaustion
8. `FTP-Patator` — Brute force credential guessing over FTP
9. `Heartbleed` — OpenSSL Heartbleed Memory Exposure Exploit
10. `Infiltration` — Lateral movement / Internal network breach
11. `PortScan` — Reconnaissance & Port Enumeration
12. `SSH-Patator` — Brute force credential guessing over SSH
13. `Web Attack – Brute Force` — Web application login brute force
14. `Web Attack – Sql Injection` — SQL Payload Injection
15. `Web Attack – XSS` — Cross-Site Scripting Injection

---

### Labels Breakdown per Dataset File

* **`Monday-WorkingHours.pcap_ISCX.csv`**
  - `BENIGN`

* **`Tuesday-WorkingHours.pcap_ISCX.csv`**
  - `BENIGN`
  - `FTP-Patator`
  - `SSH-Patator`

* **`Wednesday-workingHours.pcap_ISCX.csv`**
  - `BENIGN`
  - `DoS slowloris`
  - `DoS Slowhttptest`
  - `DoS Hulk`
  - `DoS GoldenEye`
  - `Heartbleed`

* **`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`**
  - `BENIGN`
  - `Web Attack – Brute Force`
  - `Web Attack – XSS`
  - `Web Attack – Sql Injection`

* **`Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`**
  - `BENIGN`
  - `Infiltration`

* **`Friday-WorkingHours-Morning.pcap_ISCX.csv`**
  - `BENIGN`
  - `Bot`

* **`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`**
  - `BENIGN`
  - `PortScan`

* **`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`**
  - `BENIGN`
  - `DDoS`

---

### Usage Tip for `--label`
You can pass any partial substring to `--label` when testing:
- `--label PortScan`
- `--label Web`
- `--label DDoS`
- `--label Patator`
- `--label Heartbleed`
- `--label DoS`