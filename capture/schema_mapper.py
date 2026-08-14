"""
Identify what each column of an unknown flow dataset actually IS, from its
contents as well as its name, and rename it into the project's canonical schema.

THE PROBLEM THIS SOLVES
-----------------------
Three flow datasets, three naming conventions for the same quantity:

    CICIDS2017 GeneratedLabelledFlows   "Total Length of Fwd Packets"
    CSE-CIC-IDS2018                     "TotLen Fwd Pkts"
    A's CICFlowMeter output             "totlen_fwd_pkts"

`graph_builder._COLUMN_ALIASES` matches header strings exactly, so an unknown
spelling does not raise -- the rename simply does nothing, the downstream
`if "fwd_bytes" in df.columns` is False, and every host's bytes_sent is left at
ZERO. No exception, no warning, a model trained on a dead column, and numbers
that look entirely plausible. That happened with IDS2018 and was caught by luck.

So matching on the header alone is not safe. This module fingerprints the DATA
in each column -- ranges, cardinality, IP/timestamp patterns, port
distributions -- and scores it against a profile of what each canonical field
should look like.

WHAT CONTENT ANALYSIS CANNOT DO (state this before trusting it)
----------------------------------------------------------------
Content cannot resolve DIRECTION. `fwd_bytes` and `bwd_bytes` are both
non-negative byte counts with near-identical distributions; `src_ip` and
`dst_ip` are both IPv4 columns. No amount of statistics separates them -- only
the header says which is which.

Therefore this tool combines both signals and, crucially, **refuses rather than
guesses**. A mapping is reported as LOW confidence when the header gives no
directional evidence, and `--apply` will not write a normalised file while any
required field is unresolved unless you explicitly override. A tool whose whole
purpose is preventing silent corruption must never itself silently guess.

WHERE THIS SITS IN THE PIPELINE
-------------------------------
    pcap            -> CICFlowMeter -> 76-feature CSV -> THIS -> canonical
    3rd-party CSV                                     -> THIS -> canonical

CICFlowMeter consumes packets, not flows, so a dataset that already ships as a
flow CSV can never be re-derived through it. For those, this is the only line of
defence, not a second one.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent

# Ports that dominate destination traffic but are rare as ephemeral sources.
# This is what separates dst_port from src_port on content alone.
WELL_KNOWN = {80, 443, 53, 22, 21, 25, 110, 143, 445, 139, 3389, 8080, 123, 993, 995}
EPHEMERAL_LO = 32768


# --------------------------------------------------------------------------
# Fingerprinting
# --------------------------------------------------------------------------

def _ipv4_fraction(s: pd.Series) -> float:
    sample = s.dropna().astype(str).head(500)
    if sample.empty:
        return 0.0
    ok = 0
    for v in sample:
        try:
            ipaddress.ip_address(v.strip())
            ok += 1
        except ValueError:
            pass
    return ok / len(sample)


def _datetime_fraction(s: pd.Series) -> float:
    sample = s.dropna().astype(str).head(300)
    if sample.empty:
        return 0.0
    # A bare integer parses as a datetime under many formats; require some
    # punctuation so counters are not mistaken for timestamps.
    if not sample.str.contains(r"[-/:]").any():
        return 0.0
    parsed = pd.to_datetime(sample, errors="coerce", format="mixed")
    return float(parsed.notna().mean())


def fingerprint(s: pd.Series) -> dict[str, Any]:
    """Summarise one column's contents, cheaply and without assuming a dtype."""
    n = len(s)
    nn = s.dropna()
    fp: dict[str, Any] = {
        "n": n,
        "n_unique": int(nn.nunique()) if n else 0,
        "frac_unique": float(nn.nunique() / n) if n else 0.0,
        "frac_null": float(1 - len(nn) / n) if n else 1.0,
        "ipv4_frac": 0.0,
        "datetime_frac": 0.0,
        "numeric": False,
    }
    if nn.empty:
        return fp

    num = pd.to_numeric(nn, errors="coerce")
    frac_num = float(num.notna().mean())
    if frac_num > 0.95:
        v = num.dropna()
        finite = v[np.isfinite(v)]
        fp.update({
            "numeric": True,
            "min": float(finite.min()) if len(finite) else 0.0,
            "max": float(finite.max()) if len(finite) else 0.0,
            "mean": float(finite.mean()) if len(finite) else 0.0,
            "frac_zero": float((finite == 0).mean()) if len(finite) else 0.0,
            "frac_int": float((finite == finite.round()).mean()) if len(finite) else 0.0,
            "frac_negative": float((finite < 0).mean()) if len(finite) else 0.0,
            "frac_well_known": float(finite.isin(list(WELL_KNOWN)).mean()) if len(finite) else 0.0,
            "frac_ephemeral": float((finite >= EPHEMERAL_LO).mean()) if len(finite) else 0.0,
        })
        # Exact value set for low-cardinality columns, so a protocol column can
        # be told from a binary flag column rather than merely "few distinct".
        if fp["n_unique"] <= 12:
            fp["unique_values"] = sorted(float(x) for x in finite.unique())
    else:
        fp["ipv4_frac"] = _ipv4_fraction(nn)
        fp["datetime_frac"] = _datetime_fraction(nn)
        fp["top_values"] = [str(x) for x in nn.value_counts().head(5).index]
    return fp


# --------------------------------------------------------------------------
# Canonical field profiles
# --------------------------------------------------------------------------
# tokens  : substrings whose presence in a header is evidence FOR this field
# anti    : substrings whose presence is evidence AGAINST it
# directional: True when content cannot distinguish this field from its partner,
#              so the header must carry the decision

PROFILES: dict[str, dict[str, Any]] = {
    "src_ip": {"tokens": ["src ip", "source ip", "src_ip", "srcip", "sourceip"],
               "anti": ["dst", "dest"], "directional": True, "required": True},
    "dst_ip": {"tokens": ["dst ip", "destination ip", "dst_ip", "dstip", "destinationip"],
               "anti": ["src", "source"], "directional": True, "required": True},
    "src_port": {"tokens": ["src port", "source port", "src_port", "sport"],
                 "anti": ["dst", "dest"], "directional": True, "required": False},
    "dst_port": {"tokens": ["dst port", "destination port", "dst_port", "dport"],
                 "anti": ["src", "source"], "directional": True, "required": True},
    "protocol": {"tokens": ["protocol", "proto"], "anti": [], "directional": False,
                 "required": False},
    "timestamp": {"tokens": ["timestamp", "time", "date"], "anti": ["duration"],
                  "directional": False, "required": True},
    "label": {"tokens": ["label", "class", "attack", "category"], "anti": [],
              "directional": False, "required": False},
    "flow_duration": {"tokens": ["flow duration", "duration"], "anti": ["idle", "active"],
                      "directional": False, "required": False},
    "fwd_bytes": {"tokens": ["totlen fwd", "total length of fwd", "totlen_fwd_pkts",
                             "fwd bytes", "bytes sent", "src bytes"],
                  "anti": ["bwd", "backward", "mean", "std", "max", "min", "/s", "avg"],
                  "directional": True, "required": False},
    "bwd_bytes": {"tokens": ["totlen bwd", "total length of bwd", "totlen_bwd_pkts",
                             "bwd bytes", "bytes recv", "dst bytes"],
                  "anti": ["fwd", "forward", "mean", "std", "max", "min", "/s", "avg"],
                  "directional": True, "required": False},
    "fwd_pkts": {"tokens": ["tot fwd pkts", "total fwd packets", "tot_fwd_pkts",
                            "fwd packets", "fwd pkts"],
                 "anti": ["bwd", "backward", "len", "length", "/s", "mean", "std", "subflow"],
                 "directional": True, "required": False},
    "bwd_pkts": {"tokens": ["tot bwd pkts", "total backward packets", "tot_bwd_pkts",
                            "bwd packets", "bwd pkts"],
                 "anti": ["fwd", "forward", "len", "length", "/s", "mean", "std", "subflow"],
                 "directional": True, "required": False},
}


def _norm(name: str) -> str:
    return re.sub(r"[_\-]+", " ", str(name).strip().lower())


def name_score(col: str, prof: dict) -> float:
    """How strongly the HEADER suggests this field. 0 when an anti-token hits."""
    c = _norm(col)
    for bad in prof["anti"]:
        if bad in c:
            return 0.0
    best = 0.0
    for tok in prof["tokens"]:
        t = _norm(tok)
        if c == t:
            return 1.0
        if t in c:
            best = max(best, 0.75 + 0.2 * len(t) / max(len(c), 1))
    return best


def content_score(field: str, fp: dict) -> float:
    """How strongly the DATA is consistent with this field. Never proves direction."""
    if fp.get("n_unique", 0) == 0:
        return 0.0
    num = fp.get("numeric", False)

    if field in ("src_ip", "dst_ip"):
        return fp.get("ipv4_frac", 0.0)
    if field == "timestamp":
        return fp.get("datetime_frac", 0.0)
    if field == "label":
        if num or fp.get("n_unique", 0) > 40:
            return 0.0
        tops = " ".join(fp.get("top_values", [])).lower()
        hit = any(k in tops for k in ("benign", "normal", "attack", "dos", "ddos",
                                      "portscan", "bot", "infiltration", "patator",
                                      "brute", "xss", "sql", "heartbleed"))
        return 0.9 if hit else 0.4
    if field in ("src_port", "dst_port"):
        if not num or fp.get("frac_int", 0) < 0.99:
            return 0.0
        if fp.get("min", -1) < 0 or fp.get("max", 1e9) > 65535:
            return 0.0
        # The one real content discriminator between the two: destinations
        # concentrate on well-known services, sources spread over ephemerals.
        wk, eph = fp.get("frac_well_known", 0.0), fp.get("frac_ephemeral", 0.0)
        if field == "dst_port":
            return float(np.clip(0.5 + wk - 0.5 * eph, 0.0, 1.0))
        return float(np.clip(0.5 + 0.5 * eph - wk, 0.0, 1.0))
    if field == "protocol":
        if not num:
            return 0.0
        vals = fp.get("unique_values")
        # A binary 0/1 column is a FLAG, not a protocol. Without this, every
        # "Fwd PSH Flags"-style column scores as well as the real Protocol
        # column on content alone, purely for having low cardinality.
        if vals is not None and set(vals) <= {0.0, 1.0}:
            return 0.0
        # Real IP protocol numbers, not just "some small integers".
        if vals is not None and set(vals) <= {0.0, 1.0, 2.0, 6.0, 17.0, 41.0,
                                              47.0, 50.0, 58.0, 89.0, 132.0}:
            return 0.95
        return 0.1 if fp.get("max", 1e9) <= 255 else 0.0
    if field in ("fwd_bytes", "bwd_bytes", "fwd_pkts", "bwd_pkts", "flow_duration"):
        if not num or fp.get("frac_negative", 1.0) > 0.01:
            return 0.0
        if field.endswith("_pkts"):
            return 0.8 if fp.get("frac_int", 0) > 0.99 else 0.2
        return 0.7
    return 0.0


def map_schema(df: pd.DataFrame) -> dict[str, dict]:
    """Assign each canonical field its best column. One column, one field."""
    fps = {c: fingerprint(df[c]) for c in df.columns}

    cands = []
    for field, prof in PROFILES.items():
        for col in df.columns:
            ns = name_score(col, prof)
            cs = content_score(field, fps[col])
            if ns == 0.0 and cs == 0.0:
                continue
            # Content is the veto, the header is the tie-breaker. A column whose
            # contents are impossible for a field (cs == 0) is rejected however
            # perfect its name -- that is what catches a "Dst Port" column that
            # actually holds an incrementing counter.
            if cs == 0.0:
                continue
            combined = 0.6 * ns + 0.4 * cs if ns > 0 else 0.4 * cs
            cands.append((combined, field, col, ns, cs))

    cands.sort(key=lambda t: -t[0])
    out: dict[str, dict] = {}
    used: set[str] = set()
    for combined, field, col, ns, cs in cands:
        if field in out or col in used:
            continue
        prof = PROFILES[field]
        # Directional fields need the header. Content alone cannot tell fwd from
        # bwd or src from dst, so a match with no name evidence is a guess.
        if prof["directional"] and ns == 0.0:
            confidence = "REFUSED"
        elif combined >= 0.75:
            confidence = "high"
        elif combined >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"
        if confidence == "REFUSED":
            continue
        # A field with no name evidence and only weak content evidence is a
        # coincidence, not a match. Reporting "not found" is strictly more
        # useful than naming an arbitrary column at low confidence, because a
        # reader skims the table and sees a filled cell.
        if combined < 0.35:
            continue
        out[field] = {"column": col, "confidence": confidence,
                      "score": round(combined, 3),
                      "name_score": round(ns, 3), "content_score": round(cs, 3),
                      "fingerprint": fps[col]}
        used.add(col)
    return out


def apply_mapping(df: pd.DataFrame, mapping: dict[str, dict]) -> pd.DataFrame:
    rename = {m["column"]: field for field, m in mapping.items()}
    return df.rename(columns=rename)


def report(path: Path, mapping: dict[str, dict], df: pd.DataFrame) -> list[str]:
    lines = [f"# Schema map — {path.name}", "",
             f"{len(df.columns)} columns, {len(df):,} rows sampled.", "",
             "| canonical field | matched column | confidence | name | content |",
             "| --- | --- | --- | --- | --- |"]
    for field in PROFILES:
        m = mapping.get(field)
        if m:
            lines.append(f"| `{field}` | `{m['column']}` | {m['confidence']} "
                         f"| {m['name_score']:.2f} | {m['content_score']:.2f} |")
        else:
            req = " **(REQUIRED)**" if PROFILES[field]["required"] else ""
            lines.append(f"| `{field}` | — not found —{req} | — | — | — |")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Identify and normalise an unknown flow dataset's schema.")
    ap.add_argument("csv")
    ap.add_argument("--sample", type=int, default=20000,
                    help="rows to read for fingerprinting")
    ap.add_argument("--apply", action="store_true",
                    help="write a normalised copy with canonical column names")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--force", action="store_true",
                    help="write even when a required field is unresolved")
    args = ap.parse_args()

    path = Path(args.csv).resolve()
    if not path.exists():
        raise SystemExit(f"no such file: {path}")

    sys.path.insert(0, str(REPO_ROOT / "detection"))
    from graph_builder import read_flows  # noqa: E402

    df = read_flows(path, limit=args.sample)
    df.columns = [str(c).strip() for c in df.columns]
    mapping = map_schema(df)

    lines = report(path, mapping, df)
    print("\n".join(lines))

    missing = [f for f, p in PROFILES.items() if p["required"] and f not in mapping]
    weak = [f for f, m in mapping.items() if m["confidence"] == "low"]
    # The most useful thing this tool can report: the header is confident and
    # the data disagrees with it. That is not a naming problem, it is a DATA
    # problem, and it is invisible to any alias-table approach.
    # training_data/live_capture.csv is the worked example -- its `dst_port`
    # matches by name perfectly but holds an incrementing counter, giving 12,503
    # "services" across 12,504 flows (CLAUDE.md gotcha #6).
    suspect = [(f, m) for f, m in mapping.items()
               if m["name_score"] >= 0.9 and m["content_score"] < 0.6]

    if missing:
        print(f"\nMISSING REQUIRED: {', '.join(missing)}")
        if {"src_ip", "dst_ip"} & set(missing):
            print("  Without IP columns this dataset cannot build a graph at all "
                  "(CLAUDE.md gotcha #3). It can still feed the per-flow baseline.")
    if weak:
        print(f"\nLOW CONFIDENCE (check by hand): {', '.join(weak)}")

    if suspect:
        print("\nHEADER/CONTENT DISAGREEMENT — the name fits, the data does not:")
        for f, m in suspect:
            print(f"  `{f}` <- `{m['column']}`  name={m['name_score']:.2f} "
                  f"content={m['content_score']:.2f}")
            if f in ("dst_port", "src_port"):
                fpv = m["fingerprint"]
                print(f"     {fpv.get('n_unique', 0):,} distinct values across "
                      f"{fpv.get('n', 0):,} rows "
                      f"({100 * fpv.get('frac_well_known', 0):.1f}% well-known ports)")
                print("     A real destination-port column concentrates on 80/443/53. "
                      "Near-unique values mean a counter or an ID, not a service.")
        print("  These columns are named correctly and hold the wrong thing. "
              "An alias table cannot see this; check before training.")

    if args.apply:
        if missing and not args.force:
            raise SystemExit(
                "\nRefusing to write: required fields unresolved. Inspect the "
                "table above and pass --force only if you have verified the "
                "mapping yourself. Writing a wrong mapping is worse than writing "
                "nothing -- it produces plausible numbers from the wrong columns.")
        full = read_flows(path, limit=None)
        full.columns = [str(c).strip() for c in full.columns]
        out = Path(args.out) if args.out else path.with_suffix(".canonical.csv")
        apply_mapping(full, mapping).to_csv(out, index=False)
        print(f"\nWrote {out}  ({len(full):,} rows)")

    js = path.with_suffix(".schema.json")
    js.write_text(json.dumps(
        {f: {k: v for k, v in m.items() if k != "fingerprint"}
         for f, m in mapping.items()}, indent=2), encoding="utf-8")
    print(f"Wrote {js.name}")


if __name__ == "__main__":
    main()
