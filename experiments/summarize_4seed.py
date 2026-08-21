import json
import numpy as np

r = json.load(open("experiments/multiwindow_4seed_band.json"))
fams = sorted({f for s in r.values() for f in s})
print(f"{'Family':<20} {'mean':>7} {'std':>7}  seeds")
for f in fams:
    v = [r[str(s)][f]["auc"] for s in range(4)]
    print(f"{f:<20} {np.mean(v):>7.4f} {np.std(v):>7.4f}  {v}")
means = [np.mean([r[str(s)][f]["auc"] for f in r[str(s)]]) for s in range(4)]
print("per-seed means:", [round(m, 4) for m in means])
print("band: %.4f +/- %.4f" % (np.mean(means), np.std(means, ddof=1)))
p100 = [np.mean([r[str(s)][f]["p100"] for f in r[str(s)]]) for s in range(4)]
print("mean P@100: %.4f" % np.mean(p100))
