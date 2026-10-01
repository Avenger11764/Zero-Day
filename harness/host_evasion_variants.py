"""
host_evasion_variants.py -- Evasion Scenario Generator for Host Telemetry
========================================================================
Role D: Adversarial Eval & Delivery (Person D - Avinash)
Zero-Day Detection FYP - Week 5

PURPOSE:
--------
Reads the verified kill-chain trace (`host_attack_story_trace.jsonl`) and generates
adversarial evasion variants designed to bypass the Host-AE by perturbing n-gram
frequencies and inter-arrival timing dynamics.

NOTE: 
Scoring against the Host-AE is currently PENDING. Person B has shipped a baseline
Host Autoencoder, but it is currently hardcoded to consume a simple V+3 count
vector instead of Person A's new 128-D `HostFeatureVector`. Until `host_ae.py` 
natively ingests the 128-D vector, we cannot run true adversarial scoring.

VARIANTS GENERATED:
-------------------
1. Feature Padding (Benign Syscall Injection)
   Injects high volumes of `openat`/`read`/`close` loops to drown out the frequency
   of critical syscalls (like `ptrace` and `setuid`), targeting the 1-Gram Block.

2. Timing Morph (Drip Execution)
   Stretches inter-arrival timestamps from milliseconds to hours to evade the Timing
   Dynamics block (mean/std Δt, burstiness).
"""

import json
import copy
from pathlib import Path

def generate_variants(input_trace_path: str, out_dir: str):
    trace_path = Path(input_trace_path)
    if not trace_path.exists():
        print(f"Error: {input_trace_path} not found.")
        return

    with open(trace_path, 'r') as f:
        original = [json.loads(l) for l in f]

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1. Feature Padding Variant
    padding_variant = []
    for rec in original:
        padding_variant.append(rec)
        if rec.get("is_attack"):
            # Inject 50 benign openat/close calls around malicious calls
            for _ in range(5):
                pad1 = copy.deepcopy(rec)
                pad1["syscall"] = "openat"
                pad1["args"] = {"dfd": -100, "filename": "/lib/x86_64-linux-gnu/libc.so.6", "flags": 0, "mode": 0}
                pad1["is_attack"] = False
                pad1["timestamp"] += 0.001
                padding_variant.append(pad1)
                
                pad2 = copy.deepcopy(rec)
                pad2["syscall"] = "close"
                pad2["args"] = {"fd": 3}
                pad2["is_attack"] = False
                pad2["timestamp"] += 0.002
                padding_variant.append(pad2)
    
    with open(out / "variant_padding.jsonl", "w") as f:
        for r in padding_variant:
            f.write(json.dumps(r) + "\n")
    print(f"[*] Generated Padding Variant: {len(padding_variant)} records")

    # 2. Timing Morph Variant
    timing_variant = copy.deepcopy(original)
    time_offset = 0
    for i, rec in enumerate(timing_variant):
        if rec.get("is_attack"):
            time_offset += 3600.0  # delay each attack step by 1 hour
        rec["timestamp"] += time_offset
    
    with open(out / "variant_timing.jsonl", "w") as f:
        for r in timing_variant:
            f.write(json.dumps(r) + "\n")
    print(f"[*] Generated Timing Morph Variant: {len(timing_variant)} records")

    print("\n[NOTE] Evasion trace generation complete. Scoring pending B's 128-D AE integration.")

if __name__ == "__main__":
    generate_variants("harness/results/host_attack_story_trace.jsonl", "harness/results/evasion_variants")
