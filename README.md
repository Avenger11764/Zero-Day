# Zero-Day

Drift-Aware Explainable Anomaly Detection for Behavioral Threat Hunting.

## Setup (do this once per machine)

The `venv/` folder is **machine-specific and is not tracked**. Never copy it
between the PC and the laptop — it hardcodes absolute paths and will break.
Build a fresh one on each machine instead:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On a machine without an NVIDIA GPU, edit `requirements.txt` first: drop the
`--extra-index-url` line and change `torch==2.5.1+cu121` to `torch==2.5.1`.

### Datasets (also untracked — `data/` is gitignored)

Both machines need these downloaded locally; they never travel through git.

| Path | What | Source |
| --- | --- | --- |
| `data/MachineLearningCSV/` | CICIDS2017, 79 cols, **no IP columns** | CIC |
| `data/GeneratedLabelledFlows/` | CICIDS2017, 85 cols, **has Flow ID / Source IP / Destination IP / Protocol / Timestamp** — required for graph construction | CIC |
| `training_data/` | A's CICFlowMeter output (tracked) | in repo |

CICIDS2017 downloads are behind a registration form at
http://cicresearch.ca/CICDataset/CIC-IDS-2017/ — fill it in with real details,
you will be citing this dataset. Skip the PCAPs (~50 GB); you only need the CSVs.

## Running

Run the detector with the batch launcher:

```bat
run_detector.bat
```

If you want to use PowerShell directly, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_detector.ps1
```

In VS Code, open `detection/stub_detector.py` and use the top-right Run button,
or pick `Python: Stub Detector` from Run and Debug.

## Path convention

All scripts resolve data paths **relative to the repo root** via
`Path(__file__).resolve().parent...`. Never hardcode an absolute path — that is
what broke every script when the project moved from `D:\Test OD\` to this machine.
