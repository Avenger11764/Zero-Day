"""
Host syscall autoencoder — Pillar 3 skeleton (Week 4).

Reuses the network AE plumbing so the host detector is near-zero-marginal-cost:

  legacy:  Flow AE  76 ->256->128->32 ->128->256->76   (M5a)
  network: Revived 87-dim ctx AE (M5a-R)
  host:    THIS FILE  N ->64->32->16->8 ->16->32->64->N  (Pillar 3, mmap says N→64→32→16→8→16→32→64→N)

Why this shape
--------------
Same thesis as M5b: autoencoder, benign-only, reconstruction = anomaly.
Syscalls are a language — normal programs make stable 6-gram patterns
(Forrest et al. 1996). Malware perturbs the sequence (ptrace, init_module
etc.). No attack label needed -> zero-day, and ablation stays comparable.

Contract (roadmap: Knowledge/roadmap_weeks4-6_after_pillar3_integration.md:4)
-------------
  A -> SyscallRecord (eBPF/BCC tracepoints) -> FeatureVector host block -> B (this file) -> host score -> C (ensembler 3-way) -> ScoredAlert

Week-4 scope: SKELETON only. No eBPF collector yet (A), no LID-DS loader yet.
Runs standalone on SYNTHETIC syscalls (no download). When LID-DS lands,
replace _synthetic_syscalls() with LID-DS loader — same train()/score API.

    python detection/host_ae.py              # self-test (no dataset)
    python detection/host_ae.py --help
    python detection/host_ae.py --n 66 --epochs 40 --seed 0   # Guo 66-dim
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

# ── paths ────────────────────────────────────────────────────────────────
OUT_DIR = Path(__file__).resolve().parent
MODEL_PATH = OUT_DIR / "host_autoencoder.pt"   # not tracked until LID-DS trained


# ── model ─────────────────────────────────────────────────_______________
class HostAutoencoder(nn.Module):
    """N ->64->32->16->8 bottleneck ->16->32->64->N, Sigmoid out, MSE scored.

    Mirrors legacy.Autoencoder but with the roadmap's narrower taper
    (64 not 256) — host feature dim N is typically 10-66, not 76,
    so 256-wide would be overkill. Bottleneck 8 keeps M5a parity.
    """

    def __init__(self, input_dim: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(),
            nn.Linear(64, 32), nn.ReLU(),
            nn.Linear(32, 16), nn.ReLU(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.ReLU(),
            nn.Linear(16, 32), nn.ReLU(),
            nn.Linear(32, 64), nn.ReLU(),
            nn.Linear(64, input_dim), nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    @torch.no_grad()
    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        return torch.mean((self.forward(x) - x) ** 2, dim=1)


class HostScaler:
    """log1p + min-max identical to gnn_model.NodeScaler(log=True).

    Syscall n-gram counts are heavy-tailed too (openat bursts).
    Fitted on BENIGN only.
    """

    def __init__(self, log: bool = True):
        self.log = log
        self.lo = None
        self.hi = None

    def _prep(self, x: torch.Tensor) -> torch.Tensor:
        if self.log:
            return torch.log1p(torch.clamp(x, min=0))
        return x

    def fit(self, X: torch.Tensor):
        P = self._prep(X)
        self.lo = P.min(dim=0).values
        self.hi = P.max(dim=0).values
        return self

    def transform(self, x: torch.Tensor) -> torch.Tensor:
        x = self._prep(x)
        span = torch.where((self.hi - self.lo) > 0, self.hi - self.lo, torch.ones_like(self.hi))
        return torch.clamp((x - self.lo) / span, 0.0, 1.0)

    def state_dict(self):
        return {"lo": self.lo, "hi": self.hi, "log": self.log}

    def load_state_dict(self, d):
        self.lo, self.hi = d["lo"], d["hi"]
        self.log = bool(d.get("log", False))
        return self


def set_seed(seed: int = 0):
    import os
    os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def train(X_benign: torch.Tensor, epochs: int = 40, lr: float = 1e-3,
          log_scale: bool = True, seed: int | None = None, device=None, quiet=False):
    """Train on BENIGN host vectors only (zero-day). Returns (model, scaler, losses)."""
    if seed is not None:
        set_seed(seed)
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    scaler = HostScaler(log=log_scale).fit(X_benign)
    Xn = scaler.transform(X_benign).to(device)

    model = HostAutoencoder(input_dim=X_benign.shape[1]).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    lf = nn.MSELoss()
    losses = []
    for ep in range(epochs):
        loss = lf(model(Xn), Xn)
        opt.zero_grad(); loss.backward(); opt.step()
        losses.append(float(loss.item()))
        if not quiet and ep % 10 == 0:
            print(f"  epoch {ep:3d} | loss {loss.item():.6f}")
    return model, scaler, losses


# ── synthetic syscall feature generator (no dataset) ─────────────────────
# Vocab mirrors the 8 eBPF tracepoints + common syscalls. Features are
# n-gram-ish counts + process context, collapsed to a fixed N-dim vector
# per "process window" (roadmap says LID-DS 66-dim; synthetic uses 32).

_SYSCALLS = ["openat", "read", "write", "close", "execve", "connect",
             "setuid", "clone", "ptrace", "init_module", "mount", "socket"]


def _synthetic_host_vectors(n_normal: int = 600, n_attack: int = 80,
                            n_dim: int = 32, seed: int = 0):
    """Return (X_benign, X_attack) torch tensors, N=n_dim.

    Normal: stable multinomial over {openat,read,write,close} + low process churn.
    Attack: injects ptrace/process_vm_readv pattern + init_module + setuid burst
            — same ATT&CK hooks C will map (T1055.008/T1547.006/T1548.001).
    """
    rng = np.random.default_rng(seed)
    # benign: draws from Dirichlet-like counts; encode as (n_dim) histogram + noise
    # attack: same but add spikes at indices that correspond to ptrace/init_module
    def _vec(is_attack: bool):
        base = rng.integers(5, 20, size=n_dim).astype(np.float32)
        # normal programs touch files + net moderately
        base[0:4] += rng.integers(0, 8, size=4)  # file ops
        if is_attack:
            # T1055.008: ptrace burst (index 8), T1547.006: init_module (9), T1548.001: setuid (6)
            base[8] += rng.integers(40, 80)   # ptrace spike
            base[9] += rng.integers(20, 50)   # init_module spike
            base[6] += rng.integers(15, 30)   # setuid spike
            # also inflate timing entropy dims (last 4)
            base[-4:] += rng.integers(10, 25, size=4)
        else:
            base += rng.integers(0, 3, size=n_dim)
        return base

    Xb = torch.tensor(np.stack([_vec(False) for _ in range(n_normal)]), dtype=torch.float32)
    Xa = torch.tensor(np.stack([_vec(True) for _ in range(n_attack)]), dtype=torch.float32)
    return Xb, Xa


def _self_test(n_dim: int = 32, epochs: int = 40, seed: int = 0):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Self-test: host AE N={n_dim} skeleton (device={device})\n")
    print("Step 1: build SYNTHETIC benign host vectors and train (benign-only)")
    Xb, Xa = _synthetic_host_vectors(n_dim=n_dim, seed=seed)
    print(f"  benign {tuple(Xb.shape)}  attack {tuple(Xa.shape)} (held out)")
    model, scaler, losses = train(Xb, epochs=epochs, seed=seed, device=device, quiet=False)
    print(f"  final loss {losses[-1]:.6f}")
    # save skeleton checkpoint (for ensembler 3-way wiring later)
    torch.save({"model": model.state_dict(), "scaler": scaler.state_dict(), "n_dim": n_dim}, MODEL_PATH)
    print(f"  saved -> {MODEL_PATH.name}\n")

    print("Step 2: score held-out attack vectors (should be higher)")
    with torch.no_grad():
        bn = model.anomaly_score(scaler.transform(Xb).to(device)).cpu().numpy()
        an = model.anomaly_score(scaler.transform(Xa).to(device)).cpu().numpy()
    print(f"  benign median {np.median(bn):.6f}  p95 {np.percentile(bn,95):.6f}")
    print(f"  attack median {np.median(an):.6f}  p95 {np.percentile(an,95):.6f}")
    # quick AUC
    try:
        from sklearn.metrics import roc_auc_score
        y = np.array([0]*len(bn) + [1]*len(an))
        s = np.concatenate([bn, an])
        auc = roc_auc_score(y, s)
        print(f"  ROC-AUC (synthetic) {auc:.4f}")
        print("  PASS -- host AE separates synthetic injection" if auc > 0.85 else "  check: AUC low — expected >0.85 on synthetic")
    except Exception as e:
        print(f"  (sklearn not available: {e})")
        print(f"  attack > benign? {np.median(an) > np.median(bn)}")


def main():
    ap = argparse.ArgumentParser(description="Host syscall autoencoder — Pillar 3 skeleton (week 4).")
    ap.add_argument("--n", type=int, default=32, help="host FeatureVector dim N (32 synthetic, 66 for Guo LID-DS)")
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--csv", default=None, help="LID-DS host CSV (not yet — uses synthetic if omitted)")
    args = ap.parse_args()

    if args.csv is None:
        _self_test(n_dim=args.n, epochs=args.epochs, seed=args.seed)
        return

    # future: LID-DS loader path — stub that keeps Checkpoint-1 green
    print("LID-DS loader not wired yet (week 5) — use synthetic self-test for now.")
    _self_test(n_dim=args.n, epochs=args.epochs, seed=args.seed)


if __name__ == "__main__":
    main()
