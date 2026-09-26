# Rolling captures land here

One file per chunk, named `YYYY-MM-DD_HHMM_<context>.pcap`, written by
Deck 4 -> ROLLING CAPTURE (or `python scripts/ops.py rolling --tag <context>`).
Each is archived by content hash as it lands.

**Only captures from the machine being defended belong here.** The champion is
tuned to this network. A capture taken anywhere else will fail the audit on
benign block decisions and will poison `logs/audit_baseline.json` until it is
removed from this folder AND from `archive/manifest.jsonl`.

`scripts/build_corpus_v2.py` picks these up automatically and rejects anything
that looks generated rather than captured.
