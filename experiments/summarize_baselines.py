import json
import numpy as np

d = json.load(open("experiments/baselines_4seed.json"))
pf = d["per_family"]
hdr = "family", "pca", "if", "mlpae", "ours"
print(f"{hdr[0]:<20} {hdr[1]:>7} {hdr[2]:>7} {hdr[3]:>7}   best_rank(mlpae)")
for f in sorted(pf["0"]):
    v = {n: np.mean([pf[str(s)][f][n]["auc"] for s in range(4)])
         for n in ("pca", "if", "mlpae")}
    br = min(pf[str(s)][f]["mlpae"]["best_rank"] for s in range(4))
    print(f"{f:<20} {v['pca']:>7.4f} {v['if']:>7.4f} {v['mlpae']:>7.4f}   {br}")
