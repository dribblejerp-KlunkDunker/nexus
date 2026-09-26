# Permanent archive

Created and maintained by `scripts/ops_archive.py`. Every capture, champion,
corpus, tier config, training result and audit report is recorded here once, by
content hash, with the date and provenance in `manifest.jsonl`.

This folder ships empty on purpose. The first archive sweep populates it, and
the first sweep happens automatically on the first audit or capture chunk. You
can also trigger it with `python scripts/ops.py archive`.

Nothing here is ever rotated away. The audit needs old captures to detect
regression, and a capture you discard cannot be re-recorded: that traffic
happened once.
