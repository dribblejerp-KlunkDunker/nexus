"""
NEXUS Predictive Brain - honest retraining.

What this replaces
------------------
`train_for_real.retrain_predictive_lstm` built its training set like this:

    normal_seqs = np.random.uniform(0.00, 0.25, size=(600, 30, 13))
    attack_seqs = np.random.uniform(0.40, 0.99, size=(600, 30, 13))

Two uniform noise distributions with disjoint ranges. The network converges to
~0 loss in a couple of epochs because the task is "is the mean above 0.3", and
it has never seen a packet. models/predictive_brain.onnx is that network, and
sniff_and_respond.py uses its output to drop the live blocking threshold from
0.85 to 0.70.

`train_predictive.SequenceDataset` had a subtler problem: it labelled each
window by its own last packet, so even on real data it classified the present
rather than forecasting. That is the detector's job, not the predictor's.

What this does instead
----------------------
Windows of T consecutive packets from the real merged capture timeline, each
carrying the 12 base features plus the champion's anomaly score (the 13-D
vector the runtime actually assembles in sniff_and_respond.py).

The label is whether an attack lands in the HORIZON that follows the window,
and the horizon is strictly outside the window. Headline accuracy is reported
on clean-window cases only -- windows containing no attack yet -- because those
are the only ones where a forecast is worth anything. Predicting an attack you
are already looking at is not prediction.
"""

import os
import sys
import json
import pickle
import argparse

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neat_vectorized import activate_batch

CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
BOLD = "\033[1m"; RESET = "\033[0m"


class NexusPredictiveLSTM(nn.Module):
    """Unchanged architecture -- the fault was never here, it was the data."""

    def __init__(self, input_dim: int = 13, hidden_dim: int = 32, num_layers: int = 2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.1)
        self.fc = nn.Sequential(nn.Linear(hidden_dim, 16), nn.ReLU(), nn.Linear(16, 1), nn.Sigmoid())

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])


def build_sequences(X20, y, scores, window=30, horizon=20, stride=3):
    """Sliding windows over the real timeline.

    Returns (sequences, labels, clean_mask) where clean_mask marks the windows
    that contain no attack packet -- the genuinely predictive cases.
    """
    feats13 = np.hstack([X20[:, :12], scores.reshape(-1, 1)]).astype(np.float32)
    seqs, labels, clean = [], [], []
    last = len(feats13) - window - horizon
    for i in range(0, max(0, last), stride):
        w = feats13[i:i + window]
        future = y[i + window:i + window + horizon]
        seqs.append(w)
        labels.append(1.0 if future.any() else 0.0)
        clean.append(not y[i:i + window].any())
    return (np.asarray(seqs, dtype=np.float32),
            np.asarray(labels, dtype=np.float32).reshape(-1, 1),
            np.asarray(clean, dtype=bool))


def evaluate(model, X, y, clean, thr=0.75):
    model.eval()
    with torch.no_grad():
        p = model(torch.from_numpy(X)).numpy().ravel()
    t = y.ravel()
    out = {}
    for name, mask in (("all windows", np.ones(len(t), dtype=bool)), ("clean windows only", clean)):
        if mask.sum() == 0 or len(np.unique(t[mask])) < 2:
            out[name] = None
            continue
        pm, tm = p[mask], t[mask]
        pred = pm >= thr
        tpr = float(pred[tm == 1].mean())
        fpr = float(pred[tm == 0].mean())
        # Rank-based AUC, no sklearn dependency.
        order = np.argsort(pm, kind="mergesort")
        ranks = np.empty(len(pm)); ranks[order] = np.arange(1, len(pm) + 1)
        npos, nneg = int((tm == 1).sum()), int((tm == 0).sum())
        auc = float((ranks[tm == 1].sum() - npos * (npos + 1) / 2) / (npos * nneg))
        out[name] = {"n": int(mask.sum()), "positives": npos, "tpr": tpr, "fpr": fpr, "auc": auc}
    return out


def main():
    ap = argparse.ArgumentParser(description="NEXUS predictive brain, trained on real sequences")
    ap.add_argument("--corpus", default="data/corpus_v2.npz")
    ap.add_argument("--champion", default="genomes/champion.pkl")
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--window", type=int, default=30)
    ap.add_argument("--horizon", type=int, default=20)
    ap.add_argument("--pt", default="models/predictive_brain.pt")
    ap.add_argument("--onnx", default="models/predictive_brain.onnx")
    args = ap.parse_args()

    d = np.load(args.corpus, allow_pickle=True)
    with open(args.champion, "rb") as f:
        ch = pickle.load(f)

    print(f"{BOLD}{CYAN}--- Predictive Brain: real sequences, forecast horizon {args.horizon} packets ---{RESET}")

    sets = {}
    for split in ("train", "val"):
        X20, y = d[f"X_{split}"], d[f"y_{split}"]
        s = activate_batch(ch["genome"], ch["config"], X20.astype(np.float64))
        seqs, labels, clean = build_sequences(X20, y, s, args.window, args.horizon)
        sets[split] = (seqs, labels, clean)
        print(f"  {split:5s} {len(seqs):6d} windows | {int(labels.sum())} with an attack in the horizon "
              f"| {int(clean.sum())} clean-window cases")

    Xtr, ytr, _ = sets["train"]
    Xva, yva, cva = sets["val"]
    if len(np.unique(ytr)) < 2:
        print(f"{RED}  Only one class present; cannot train. Capture more traffic.{RESET}")
        return

    loader = DataLoader(TensorDataset(torch.from_numpy(Xtr), torch.from_numpy(ytr)),
                        batch_size=64, shuffle=True)
    model = NexusPredictiveLSTM()
    # Positives are rarer than negatives here; weight them so the model cannot
    # win by predicting "quiet" forever.
    pos_w = float((ytr == 0).sum()) / max(1.0, float((ytr == 1).sum()))
    criterion = nn.BCELoss(reduction="none")
    opt = torch.optim.Adam(model.parameters(), lr=0.003)

    print(f"\n  positive class weight {pos_w:.2f}")
    for ep in range(args.epochs):
        model.train()
        tot = 0.0
        for bx, by in loader:
            opt.zero_grad()
            pred = model(bx)
            w = torch.where(by > 0.5, torch.tensor(pos_w), torch.tensor(1.0))
            loss = (criterion(pred, by) * w).mean()
            loss.backward()
            opt.step()
            tot += float(loss)
        if (ep + 1) % 5 == 0 or ep == args.epochs - 1:
            print(f"  epoch {ep+1:02d}/{args.epochs} | weighted BCE {tot/len(loader):.4f}")

    print(f"\n{BOLD}  Holdout (later time window, unseen){RESET}")
    res = evaluate(model, Xva, yva, cva)
    for name, m in res.items():
        if m is None:
            print(f"  {name:22s} not evaluable (single class in split)")
            continue
        verdict = "" if m["auc"] > 0.65 else f"{YELLOW}  <-- near chance{RESET}"
        print(f"  {name:22s} n={m['n']:5d} pos={m['positives']:5d} | AUC {m['auc']:.3f} | "
              f"TPR {m['tpr']*100:5.1f}%  FPR {m['fpr']*100:5.1f}%{verdict}")

    os.makedirs(os.path.dirname(args.pt), exist_ok=True)
    torch.save(model.state_dict(), args.pt)
    model.eval()
    torch.onnx.export(model, torch.randn(1, args.window, 13), args.onnx,
                      export_params=True, opset_version=18,
                      input_names=["packet_sequence"], output_names=["recon_probability"],
                      dynamic_axes={"packet_sequence": {0: "batch_size"}}, dynamo=False)
    with open("logs/predictive_results.json", "w") as f:
        json.dump({"window": args.window, "horizon": args.horizon,
                   "trained_on": "real capture timeline (data/corpus_v2.npz)",
                   "holdout": res}, f, indent=2, default=float)
    print(f"\n{GREEN}  wrote {args.pt}, {args.onnx}, logs/predictive_results.json{RESET}")


if __name__ == "__main__":
    main()
