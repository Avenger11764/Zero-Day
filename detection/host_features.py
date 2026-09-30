"""
Host feature extraction — Pillar 3, Week 5 (Person B, Detection Modeling).

Contract (roadmap: Knowledge/roadmap_weeks4-6_after_pillar3_integration.md:5):
  A -> SyscallRecord stream -> THIS FILE (host FeatureVector block) -> B (host_ae.py) -> host score

Two views of one trace, pinned once from BENIGN-TRAIN (cf. gotcha #5 —
never derive the column list per-file/split or the model sees misaligned
features with plausible-looking scores):

  * count vector  (for HostAutoencoder): histogram over the pinned syscall
    vocab + <UNK> bin + log10(length) + unique-rate. N = V + 3.
  * index sequence (for the HMM baseline): syscall numbers mapped to
    0..V-1, unseen numbers -> rarest-train index (documented hack so
    hmmlearn's CategoricalHMM, which sizes emissions from train, can score).

ADFA-LD layout (data/practice/raw_adfa_ld/ADFA-LD/ADFA-LD/):
  Training_Data_Master/   833 benign traces   (train, benign-only)
  Validation_Data_Master/ ~4372 benign traces (val/test benign pool)
  Attack_Data_Master/<Family>_N/*.txt, families Adduser Hydra_FTP Hydra_SSH
    Java_Meterpreter Meterpreter Web_Shell (held-out attacks)
  Traces are space-separated Linux x86-64 syscall NUMBERS; names come from
  the bundled unistd header (ADFA-LD+Syscall+List.txt, `#define __NR_x N`).

    python detection/host_features.py --root data/practice/raw_adfa_ld/ADFA-LD/ADFA-LD
    python detection/host_features.py --help
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import numpy as np

import sys

# Add parent directory to sys.path for capture module import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capture.host_feature_extractor import HostFeatureExtractor, resolve_data_root, SyscallRecord

DATA_ROOT_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "data" / "practice" / "raw_adfa_ld" / "ADFA-LD",
    Path(__file__).resolve().parent.parent / "data" / "practice" / "raw_adfa_ld" / "ADFA-LD" / "ADFA-LD",
    Path(__file__).resolve().parent.parent / "data" / "practice" / "raw_adfa_ld" / "a-labelled-version-of-the-ADFA-LD-dataset-master",
]

def get_data_root() -> Path:
    for c in DATA_ROOT_CANDIDATES:
        if c.exists() and (c / "ADFA-LD+Syscall+List.txt").exists():
            return c
    for c in DATA_ROOT_CANDIDATES:
        if c.exists():
            return c
    return DATA_ROOT_CANDIDATES[0]

DATA_ROOT = get_data_root()
NR_HEADER = DATA_ROOT / "ADFA-LD+Syscall+List.txt"
OUT_RECORDS = Path(__file__).resolve().parent.parent / "data" / "practice" / "ADFA-LD_SyscallRecords"

ATTACK_FAMS = ["Adduser", "Hydra_FTP", "Hydra_SSH", "Java_Meterpreter", "Meterpreter", "Web_Shell"]

_NR_RE = re.compile(r"#define\s+__NR_(\w+)\s+(\d+)")


# ── number <-> name ───────────────────────────────────────────────────
def load_nr_map(header: Path | None = None) -> dict[int, str]:
    """Parse `#define __NR_name N` lines -> {number: name}."""
    if header is None:
        header = NR_HEADER
    if not Path(header).exists():
        for c in DATA_ROOT_CANDIDATES:
            cand_hdr = c / "ADFA-LD+Syscall+List.txt"
            if cand_hdr.exists():
                header = cand_hdr
                break
    m: dict[int, str] = {}
    if Path(header).exists():
        for line in Path(header).read_text(errors="replace").splitlines():
            mo = _NR_RE.match(line.strip())
            if mo:
                m[int(mo.group(2))] = mo.group(1)
    return m


# ── trace loading ─────────────────────────────────────────────────────
def _read_seq(path: Path) -> list[int]:
    return [int(t) for t in path.read_text(errors="replace").split()]


def load_adfa(root: Path | str | None = None) -> list[dict]:
    """Return [{id, split, family, seq}].

    split: 'train' | 'val_benign' | 'attack'; family: None (benign) or one of ATTACK_FAMS.
    """
    if root is None or not (Path(root) / "Training_Data_Master").exists():
        root = get_data_root()
    root = Path(root)
    traces: list[dict] = []
    for p in sorted((root / "Training_Data_Master").glob("*.txt")):
        traces.append({"id": f"train/{p.name}", "split": "train", "family": None, "seq": _read_seq(p)})
    for p in sorted((root / "Validation_Data_Master").glob("*.txt")):
        traces.append({"id": f"val/{p.name}", "split": "val_benign", "family": None, "seq": _read_seq(p)})
    for famdir in sorted((root / "Attack_Data_Master").iterdir()):
        if not famdir.is_dir():
            continue
        fam = famdir.name.rsplit("_", 1)[0]  # Adduser_1 -> Adduser
        for p in sorted(famdir.rglob("*.txt")):
            traces.append({"id": f"attack/{famdir.name}/{p.name}", "split": "attack",
                           "family": fam, "seq": _read_seq(p)})
    return traces


# ── vocab (PINNED from benign-train) ──────────────────────────────────
def pin_vocab(train_seqs: list[list[int]]) -> dict:
    """Pin {num: idx} from train only + rarest-train fallback index for UNKs."""
    from collections import Counter
    counts = Counter(s for seq in train_seqs for s in seq)
    nums = sorted(counts)
    vocab = {n: i for i, n in enumerate(nums)}
    rarest = min(counts, key=lambda n: (counts[n], n))
    return {"vocab": vocab, "V": len(nums), "unk_idx": vocab[rarest],
            "counts": dict(counts)}


# ── views ─────────────────────────────────────────────────────────────
def count_vector(seq: list[int], pin: dict) -> np.ndarray:
    """Histogram over vocab + UNK mass + log10(len) + unique-rate. Dim V+3."""
    vocab, V = pin["vocab"], pin["V"]
    hist = np.zeros(V + 1, dtype=np.float32)  # last bin = unseen-number mass
    for s in seq:
        hist[vocab.get(s, V)] += 1.0
    n = max(len(seq), 1)
    extra = np.array([np.log10(n), len(set(seq)) / max(V, 1), hist[V] / n], dtype=np.float32)
    return np.concatenate([hist[:V] / n, extra]).astype(np.float32)


def index_sequence(seq: list[int], pin: dict) -> np.ndarray:
    """Map to 0..V-1 for CategoricalHMM; unseen -> rarest-train index."""
    vocab = pin["vocab"]
    unk = pin["unk_idx"]
    return np.array([vocab.get(s, unk) for s in seq], dtype=np.int32)


def to_syscall_records(trace: dict, nr: dict[int, str], pid: int = 1000) -> list[dict]:
    """One trace -> SyscallRecord list (A's schema; D's harness can replay these)."""
    return [{"timestamp": float(i) * 0.001, "pid": pid, "ppid": 1, "uid": 1000,
             "comm": trace["id"], "syscall": nr.get(s, f"nr_{s}"), "args": {}, "ret": 0}
            for i, s in enumerate(trace["seq"])]


def write_syscall_records(traces: list[dict], nr: dict[int, str],
                          outdir: Path = OUT_RECORDS) -> int:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    n = 0
    for t in traces:
        fp = outdir / (t["id"].replace("/", "__") + ".jsonl")
        with open(fp, "w") as f:
            for r in to_syscall_records(t, nr):
                f.write(json.dumps(r) + "\n")
        n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description="Host feature extraction — Pillar 3 (week 5).")
    ap.add_argument("--root", default=None)
    ap.add_argument("--write-records", action="store_true",
                    help="also emit per-trace SyscallRecord JSONL into data/practice/ADFA-LD_SyscallRecords/")
    args = ap.parse_args()

    root_dir = get_data_root() if args.root is None else Path(args.root)
    nr = load_nr_map(root_dir / "ADFA-LD+Syscall+List.txt")
    print(f"syscall numbers mapped: {len(nr)} (e.g. 257->{nr.get(257)}, 59->{nr.get(59)})")
    traces = load_adfa(root_dir)
    n_train = sum(1 for t in traces if t["split"] == "train")
    n_val = sum(1 for t in traces if t["split"] == "val_benign")
    n_atk = sum(1 for t in traces if t["split"] == "attack")
    print(f"traces: {len(traces)} (train benign {n_train}, val benign {n_val}, attack {n_atk})")
    fams: dict[str, int] = {}
    for t in traces:
        if t["family"]:
            fams[t["family"]] = fams.get(t["family"], 0) + 1
    print(f"attack families: {fams}")
    pin = pin_vocab([t["seq"] for t in traces if t["split"] == "train"])
    print(f"pinned vocab V={pin['V']} (+3 extra dims -> N={pin['V'] + 3})")
    X = np.stack([count_vector(t["seq"], pin) for t in traces if t["split"] == "train"])
    print(f"train count-matrix {tuple(X.shape)}, mean len {np.mean([len(t['seq']) for t in traces if t['split']=='train']):.0f}")
    if args.write_records:
        n = write_syscall_records(traces, nr)
        print(f"wrote {n} SyscallRecord JSONL files -> {OUT_RECORDS}")


if __name__ == "__main__":
    main()
