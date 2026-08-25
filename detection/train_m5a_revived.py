"""
Train + save the REVIVED M5a (per-flow pillar) so alert_pipeline can use it.

Output: detection/m5a_revived_ctx.pt containing
  {state_dict, canonical (76 cols), flow_lo/hi, ctx_lo/hi, ctx_names}
Architecture: RevivedAE 87->256->128->32 ->128->256->87 sigmoid (same shape as shipped v2-256).
Features: 76 pinned CICIDS2017 columns (MinMax) ++ 11 window-context dims (log1p+MinMax).
Trained on Monday GLF benign only, seeded, CUDA-deterministic.
"""
from __future__ import annotations
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import normalize_columns, read_flows, _window_key
from detection.evaluate_gnn import FLOWS
from detection.stub_detector import EXPECTED_FEATURES
from detection.exp_m5a_revival import (pin_canonical, flow_matrix, build_ctx,
                                       MinMax, CtxScaler, RevivedAE, CTX_DIMS)

OUT = Path(__file__).resolve().parent / "m5a_revived_ctx.pt"


def main(epochs=60, seed=0):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(seed); torch.cuda.manual_seed_all(seed); np.random.seed(seed)
    torch.backends.cudnn.deterministic = True; torch.backends.cudnn.benchmark = False

    tr = normalize_columns(read_flows(FLOWS / "Monday-WorkingHours.pcap_ISCX.csv"))
    tr = tr[tr["label"].astype(str).str.strip().str.upper() == "BENIGN"]
    tr = tr[tr["src_ip"].map(lambda v: isinstance(v, str)) & tr["dst_ip"].map(lambda v: isinstance(v, str))]
    wk = _window_key(tr, 60)
    canonical = pin_canonical(tr)

    fmm = MinMax().fit(flow_matrix(tr, canonical))
    csc = CtxScaler().fit(build_ctx(tr, wk))
    X = np.concatenate([fmm.transform(flow_matrix(tr, canonical)),
                        csc.transform(build_ctx(tr, wk))], axis=1)
    print(f"Training revived M5a on {X.shape[0]:,} flows x {X.shape[1]} dims ({epochs} ep)...")

    model = RevivedAE(X.shape[1]).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lf = torch.nn.MSELoss()
    Xt = torch.tensor(X)
    loader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(Xt),
                                         batch_size=4096, shuffle=True)
    for ep in range(epochs):
        tot = 0.0
        for (b,) in loader:
            b = b.to(device)
            l = lf(model(b), b)
            opt.zero_grad(); l.backward(); opt.step()
            tot += l.item() * len(b)
        if ep % 10 == 0:
            print(f"  ep{ep} loss {tot/len(Xt):.6f}")

    torch.save({
        "state_dict": model.state_dict(),
        "input_dim": X.shape[1],
        "canonical": canonical,
        "flow_lo": fmm.lo, "flow_hi": fmm.hi,
        "ctx_lo": csc.lo, "ctx_hi": csc.hi,
        "ctx_names": CTX_DIMS,
        "window_seconds": 60,
        "seed": seed,
    }, OUT)
    print(f"Saved -> {OUT}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    main(a.epochs, a.seed)
