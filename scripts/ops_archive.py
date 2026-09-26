"""
NEXUS Permanent Archive

Everything the project produces gets recorded here once, by content hash, with
the date and provenance attached: captures, champions, corpora, tier configs,
training results, audit reports and the event log.

Why content-hashed
------------------
The failure this prevents is the one that already happened in this project. A
figure was quoted in the README (2,330.3 evals/sec) that no run had produced,
and a "holdout" was validated against data it had trained on. Both were possible
because nothing tied a number to the artifact that generated it. Here a metric
can always be traced to the exact champion bytes and the exact capture bytes it
was measured on, and re-archiving an unchanged file is a no-op rather than a
duplicate.

Nothing is ever deleted or rotated away. Captures compress well (pcap is highly
redundant) and disk is cheaper than a lost baseline: the audit needs old
captures to detect regression, and a capture you discard is one you can never
re-record, because that traffic happened once.

Layout
------
    archive/
      manifest.jsonl          one append-only JSON record per archived artifact
      captures/<date>/…       pcap, gzipped
      genomes/<date>/…        champion and specialist pickles
      corpora/<date>/…        corpus_v2.npz snapshots
      reports/<date>/…        training results, audit reports, tier configs
      logs/<date>/…           event log snapshots, gzipped
"""

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

ARCHIVE_ROOT = "archive"
MANIFEST = os.path.join(ARCHIVE_ROOT, "manifest.jsonl")

GREEN = "\033[92m"; YELLOW = "\033[93m"; CYAN = "\033[96m"
BOLD = "\033[1m"; RESET = "\033[0m"

# What gets swept, and which archive subdirectory it lands in.
SWEEP = [
    ("captures", ["data/captures/*.pcap", "data/normal_traffic/*.pcap",
                  "data/continuous_baseline.pcap"], True),
    ("genomes", ["genomes/champion.pkl", "genomes/council_*.pkl",
                 "genomes/council_manifest.json"], False),
    ("corpora", ["data/corpus_v2.npz"], False),
    ("reports", ["config/tiers.json", "logs/honest_training_results.json",
                 "logs/predictive_results.json", "logs/audit_report.json",
                 "logs/benchmark_moe_results.json",
                 "logs/adversarial_stress_results.json"], False),
    ("logs", ["logs/nexus_events.log", "logs/ops_journal.md"], True),
]


def sha256_of(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_manifest() -> List[Dict]:
    if not os.path.exists(MANIFEST):
        return []
    out = []
    with open(MANIFEST, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def known_hashes() -> Dict[str, Dict]:
    return {r["sha256"]: r for r in load_manifest() if "sha256" in r}


def append_manifest(record: Dict) -> None:
    os.makedirs(ARCHIVE_ROOT, exist_ok=True)
    with open(MANIFEST, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def archive_file(path: str, kind: str, compress: bool, extra: Optional[Dict] = None,
                 seen: Optional[Dict[str, Dict]] = None) -> Optional[Dict]:
    """Archive one file unless its exact bytes are already recorded."""
    if not os.path.isfile(path):
        return None
    digest = sha256_of(path)
    seen = seen if seen is not None else known_hashes()
    if digest in seen:
        return None

    day = datetime.now().strftime("%Y-%m-%d")
    dest_dir = os.path.join(ARCHIVE_ROOT, kind, day)
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.basename(path)
    stamp = datetime.now().strftime("%H%M%S")
    dest = os.path.join(dest_dir, f"{stamp}_{digest[:8]}_{base}")

    if compress and not base.endswith(".gz"):
        dest += ".gz"
        with open(path, "rb") as src, gzip.open(dest, "wb", compresslevel=6) as out:
            shutil.copyfileobj(src, out)
    else:
        shutil.copy2(path, dest)

    record = {
        "archived_utc": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "source_path": path.replace("\\", "/"),
        "archive_path": dest.replace("\\", "/"),
        "sha256": digest,
        "source_bytes": os.path.getsize(path),
        "archive_bytes": os.path.getsize(dest),
        "source_mtime_utc": datetime.fromtimestamp(
            os.path.getmtime(path), timezone.utc).isoformat(),
    }
    if extra:
        record.update(extra)
    append_manifest(record)
    seen[digest] = record
    return record


def sweep(base_dir: str = ".", note: Optional[str] = None, quiet: bool = False) -> Dict:
    """Archive every new artifact. Safe and cheap to run as often as you like."""
    import glob as _glob

    cwd = os.getcwd()
    os.chdir(base_dir)
    try:
        seen = known_hashes()
        added, skipped, saved_bytes = [], 0, 0
        for kind, patterns, compress in SWEEP:
            for pattern in patterns:
                for path in sorted(_glob.glob(pattern)):
                    rec = archive_file(path, kind, compress,
                                       extra={"note": note} if note else None, seen=seen)
                    if rec:
                        added.append(rec)
                        saved_bytes += rec["archive_bytes"]
                    else:
                        skipped += 1

        if not quiet:
            print(f"{BOLD}{CYAN}--- Archive sweep ---{RESET}")
            if added:
                for rec in added:
                    ratio = (100.0 * rec["archive_bytes"] / max(1, rec["source_bytes"]))
                    print(f"  {GREEN}+{RESET} {rec['kind']:9s} {rec['source_path']:46s} "
                          f"{rec['source_bytes']/1024:8.1f} KiB -> {ratio:3.0f}%")
            else:
                print("  nothing new")
            print(f"  {len(added)} archived, {skipped} already present "
                  f"({saved_bytes/1024/1024:.1f} MiB written)")
        return {"added": len(added), "skipped": skipped, "records": added}
    finally:
        os.chdir(cwd)


def provenance_of(sha_prefix: str) -> List[Dict]:
    return [r for r in load_manifest() if r.get("sha256", "").startswith(sha_prefix)]


def summary() -> Dict:
    recs = load_manifest()
    by_kind: Dict[str, Dict] = {}
    for r in recs:
        k = r.get("kind", "?")
        d = by_kind.setdefault(k, {"count": 0, "bytes": 0, "first": None, "last": None})
        d["count"] += 1
        d["bytes"] += r.get("archive_bytes", 0)
        ts = r.get("archived_utc", "")
        d["first"] = min(d["first"], ts) if d["first"] else ts
        d["last"] = max(d["last"], ts) if d["last"] else ts
    return {"total_artifacts": len(recs), "by_kind": by_kind}


def main():
    ap = argparse.ArgumentParser(description="NEXUS permanent archive")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("sweep", help="archive every new artifact")
    s.add_argument("--note", type=str, default=None)
    sub.add_parser("summary", help="what is archived")
    t = sub.add_parser("trace", help="find an artifact by sha256 prefix")
    t.add_argument("sha")
    args = ap.parse_args()

    if args.cmd == "summary":
        s = summary()
        print(f"{BOLD}Archive: {s['total_artifacts']} artifacts{RESET}")
        for kind, d in sorted(s["by_kind"].items()):
            print(f"  {kind:10s} {d['count']:5d} files  {d['bytes']/1024/1024:8.1f} MiB  "
                  f"{(d['first'] or '')[:10]} .. {(d['last'] or '')[:10]}")
    elif args.cmd == "trace":
        for r in provenance_of(args.sha):
            print(json.dumps(r, indent=2, sort_keys=True))
    else:
        sweep(note=getattr(args, "note", None))


if __name__ == "__main__":
    main()
