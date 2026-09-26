"""
NEXUS Genome Vault
==================

Replaces raw `pickle.load()` for every genome file the RUNTIME loads.

Why: `pickle` restores arbitrary Python objects, which means executing
attacker-controlled code. A genome file is not trusted input -- it can be
swapped on disk, shipped inside a "model pack", or replaced by anything that
gains write access to `genomes/`. The dashboard and the live guardian both
load genomes at startup on an elevated process, so a malicious `champion.pkl`
is remote-code-execution-by-file-swap.

Design:
  * Signed container: MAGIC + canonical JSON payload + HMAC-SHA256 tag.
  * The HMAC key lives in `config/genome_key.hex` (created on first use,
    32 random bytes, hex). It signs; it is not a secret from the local user,
    but it makes every genome TAMPER-EVIDENT: a swapped or modified file
    fails verification loudly instead of executing.
  * Payloads are JSON (no code execution at load, ever).
  * Backward compatible: loaders accept the legacy `.pkl` (with a warning)
    and prefer `<name>.ngenome` when both exist.
  * Migration never deletes: `migrate` writes `.ngenome` beside each `.pkl`.

CLI:
    python scripts/genomevault.py migrate            # sign all genomes/*.pkl
    python scripts/genomevault.py verify genomes/champion.ngenome
    python scripts/genomevault.py selftest
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import sys

MAGIC = b"NEXUS-GENOME-V1"
DEFAULT_KEY_PATH = os.environ.get("NEXUS_GENOME_KEY", "config/genome_key.hex")


class GenomeVaultError(RuntimeError):
    """Raised on malformed, tampered, or unverifiable genome containers."""


# --------------------------------------------------------------------------
# Key management
# --------------------------------------------------------------------------

def load_key(key_path: str = DEFAULT_KEY_PATH, create: bool = True) -> bytes:
    """Load (or create) the signing key. Hex-encoded 32 bytes on disk."""
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise GenomeVaultError(f"Key file {key_path} is not valid hex") from exc
        if len(key) < 32:
            raise GenomeVaultError(f"Key file {key_path} too short ({len(key)} bytes)")
        return key
    if not create:
        raise GenomeVaultError(f"Key file {key_path} not found; run 'genomevault.py migrate' first")
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    key = secrets.token_bytes(32)
    # Write with restrictive permissions where the OS supports it.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key.hex())
    print(f"[GenomeVault] Generated new signing key: {key_path}")
    return key


# --------------------------------------------------------------------------
# Canonical serialization + HMAC sealing
# --------------------------------------------------------------------------

def canonical_json(payload: dict) -> bytes:
    """Deterministic JSON bytes -- same dict, same bytes, every time."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def seal_payload(payload: dict, key: bytes) -> bytes:
    """MAGIC || canonical_json || HMAC tag."""
    body = canonical_json(payload)
    tag = hmac.new(key, MAGIC + body, hashlib.sha256).hexdigest()
    return MAGIC + body + b"|" + tag.encode("ascii")


def open_payload(blob: bytes, key: bytes) -> dict:
    """Verify and open a sealed payload. Raises GenomeVaultError on any tamper."""
    if not blob.startswith(MAGIC):
        raise GenomeVaultError("not a NEXUS genome container (missing MAGIC)")
    rest = blob[len(MAGIC):]
    if b"|" not in rest:
        raise GenomeVaultError("container is truncated (no HMAC tag)")
    body, tag = rest.rsplit(b"|", 1)
    expected = hmac.new(key, MAGIC + body, hashlib.sha256).hexdigest()
    # Compare BYTES: a corrupted tag can contain arbitrary non-ASCII bytes,
    # and compare_digest on str raises TypeError for non-ASCII input instead
    # of returning False. Found by tests/test_genomevault.py -- the verifier
    # must reject corruption cleanly, never crash on it.
    if not hmac.compare_digest(expected.encode("ascii"), tag):
        raise GenomeVaultError(
            "HMAC verification FAILED -- genome file was modified, swapped, or "
            "corrupted. Refusing to load. Re-run 'genomevault.py migrate' only "
            "if you trust this file.")
    try:
        return json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GenomeVaultError(f"container payload is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------
# NEAT genome <-> dict conversion (neat is imported lazily, only here)
# --------------------------------------------------------------------------

def _require_neat():
    try:
        import neat  # noqa: F401
    except ImportError as exc:
        raise GenomeVaultError(
            "neat-python is required for genome pack/unpack (pip install neat-python)") from exc
    return neat


def genome_to_dict(genome, config) -> dict:
    """Flatten a neat DefaultGenome into a JSON-safe dict."""
    nodes = {}
    for nk, node in genome.nodes.items():
        nodes[str(nk)] = {
            "bias": node.bias,
            "response": node.response,
            "activation": node.activation,
            "aggregation": node.aggregation,
        }
    conns = {}
    for ck, conn in genome.connections.items():
        conns[f"{ck[0]}->{ck[1]}"] = {
            "weight": conn.weight,
            "enabled": bool(conn.enabled),
        }
    n_inputs = len(config.genome_config.input_keys) if config is not None else None
    return {
        "key": int(genome.key),
        "fitness": float(getattr(genome, "fitness", 0.0) or 0.0),
        "num_inputs": n_inputs,
        "nodes": nodes,
        "connections": conns,
    }


def _make_config(config_text: str):
    """Build a live NEAT Config from stored text.

    neat-python's Config constructor has accepted both filenames and file-like
    objects across versions; this tries the file-like path first and falls
    back to a temp file so the vault works on either behavior.
    """
    neat = _require_neat()
    if not config_text:
        raise GenomeVaultError(
            "payload has no config_text; cannot rebuild the network "
            "(re-migrate from the original pickle)")
    try:
        return neat.config.Config(
            neat.DefaultGenome, neat.DefaultReproduction,
            neat.DefaultSpeciesSet, neat.DefaultStagnation,
            io.StringIO(config_text))
    except TypeError:
        import tempfile
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        try:
            tf.write(config_text)
            tf.close()
            return neat.config.Config(
                neat.DefaultGenome, neat.DefaultReproduction,
                neat.DefaultSpeciesSet, neat.DefaultStagnation, tf.name)
        finally:
            try:
                os.unlink(tf.name)
            except OSError:
                pass


def dict_to_genome(payload: dict):
    """Rebuild a live neat genome + config from a vault payload dict."""
    neat = _require_neat()
    local = _make_config(payload.get("config_text") or "")

    g = neat.DefaultGenome(payload.get("key", 0))
    g.fitness = payload.get("fitness", 0.0)

    g.nodes = {}
    for nk_str, nd in (payload.get("nodes") or {}).items():
        nk = int(nk_str)
        node = local.genome_config.node_gene_type(nk)
        node.bias = float(nd.get("bias", 0.0))
        node.response = float(nd.get("response", 1.0))
        node.activation = nd.get("activation", "sigmoid")
        node.aggregation = nd.get("aggregation", "sum")
        g.nodes[nk] = node

    g.connections = {}
    for ck_str, cd in (payload.get("connections") or {}).items():
        in_k, out_k = ck_str.split("->")
        conn = local.genome_config.connection_gene_type(
            (int(in_k), int(out_k)))
        conn.weight = float(cd.get("weight", 0.0))
        conn.enabled = bool(cd.get("enabled", True))
        g.connections[(int(in_k), int(out_k))] = conn

    return g, local


def pack_pickle(pkl_path: str, out_path: str, key: bytes) -> dict:
    """Read a legacy {genome, config} pickle and write a signed .ngenome."""
    _require_neat()
    import pickle
    with open(pkl_path, "rb") as f:
        data = pickle.load(f)
    genome = data.get("genome")
    config = data.get("config")
    if genome is None:
        raise GenomeVaultError(f"{pkl_path} does not contain a 'genome' entry")

    buf = io.StringIO()
    if config is not None:
        config.save_config(buf)
    payload = {
        "genome": genome_to_dict(genome, config),
        "config_text": buf.getvalue(),
        "migrated_from": os.path.basename(pkl_path),
    }
    blob = seal_payload(payload, key)
    with open(out_path, "wb") as f:
        f.write(blob)
    return {"source": pkl_path, "out": out_path,
            "nodes": len(payload["genome"]["nodes"]),
            "connections": len(payload["genome"]["connections"]),
            "bytes": len(blob)}


def load_sealed(path: str, key: bytes = None) -> dict:
    """Open a signed container and return its payload dict."""
    key = key or load_key()
    with open(path, "rb") as f:
        return open_payload(f.read(), key)


def load_genome_and_config(path: str, key: bytes = None):
    """Resolve a genome path to a live (genome, config) pair.

    Prefers the sealed `<stem>.ngenome` beside the given name; falls back to
    the legacy pickle with a loud warning. Raises GenomeVaultError when
    neither exists.
    """
    root, _ = os.path.splitext(path)
    sealed_path = root + ".ngenome"
    if os.path.exists(sealed_path):
        payload = load_sealed(sealed_path, key)
        return dict_to_genome(payload)
    if os.path.exists(path):
        # Legacy path -- allowed, but loudly. This is the only place a pickle
        # should still be opened at runtime.
        print(f"[GenomeVault] WARNING: {path} is UNSIGNED legacy pickle; "
              f"run 'python scripts/genomevault.py migrate' to sign it")
        import pickle
        with open(path, "rb") as f:
            data = pickle.load(f)
        return data["genome"], data.get("config")
    raise GenomeVaultError(f"no genome found at {path} (or {sealed_path})")


def load_network(path: str, key: bytes = None):
    """Convenience for runtime loaders: returns (network, num_inputs, fitness)."""
    neat = _require_neat()
    genome, config = load_genome_and_config(path, key)
    net = neat.nn.FeedForwardNetwork.create(genome, config)
    n_in = len(config.genome_config.input_keys) if config is not None else None
    fit = float(getattr(genome, "fitness", 0.0) or 0.0)
    return net, n_in, fit


def migrate_all(genomes_dir: str = "genomes", key_path: str = DEFAULT_KEY_PATH) -> list:
    """Sign every genome pickle that has a matching {genome, config} payload."""
    key = load_key(key_path)
    results = []
    if not os.path.isdir(genomes_dir):
        print(f"[GenomeVault] no {genomes_dir} directory")
        return results
    for name in sorted(os.listdir(genomes_dir)):
        if not name.endswith(".pkl") or name.startswith("neat-checkpoint"):
            continue
        src = os.path.join(genomes_dir, name)
        dst = os.path.splitext(src)[0] + ".ngenome"
        try:
            results.append(pack_pickle(src, dst, key))
            r = results[-1]
            print(f"[GenomeVault] sealed {name} -> {os.path.basename(dst)} "
                  f"({r['nodes']} nodes / {r['connections']} conns)")
        except GenomeVaultError as exc:
            print(f"[GenomeVault] skipped {name}: {exc}")
        except Exception as exc:
            print(f"[GenomeVault] skipped {name}: unpickle failed ({exc}) -- "
                  f"not a NEXUS champion file?")
    return results


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _cli(argv: list) -> int:
    if argv and argv[0] == "migrate":
        results = migrate_all()
        print(f"\n[GenomeVault] {len(results)} genome(s) sealed. "
              f"Loaders now prefer the .ngenome files; originals left in place.")
        return 0
    if argv and argv[0] == "verify" and len(argv) > 1:
        payload = load_sealed(argv[1])
        g = payload.get("genome", {})
        print(f"OK: {argv[1]} (key={g.get('key')}, nodes={len(g.get('nodes') or {})}, "
              f"connections={len(g.get('connections') or {})}, "
              f"fitness={g.get('fitness')})")
        return 0
    if argv and argv[0] == "selftest":
        return _selftest()
    print(__doc__)
    return 2


def _selftest() -> int:
    failures = []

    def check(name, cond):
        print(("PASS  " if cond else "FAIL  ") + name)
        if not cond:
            failures.append(name)

    key = secrets.token_bytes(32)
    payload = {"genome": {"key": 1, "fitness": 0.99,
                          "nodes": {"0": {"bias": 0.5}},
                          "connections": {"0->2": {"weight": 1.5, "enabled": True}}},
               "config_text": "[NEAT]\nfitness_criterion = max\n"}

    # Round-trip
    blob = seal_payload(payload, key)
    opened = open_payload(blob, key)
    check("round-trip", opened == payload)

    # Deterministic sealing
    check("canonical bytes", seal_payload(payload, key) == blob)

    # Tamper detection: flip a weight
    tampered = blob.replace(b"1.5", b"9.9")
    try:
        open_payload(tampered, key)
        check("tamper detected (weight flip)", False)
    except GenomeVaultError:
        check("tamper detected (weight flip)", True)

    # Tamper detection: fitness inflation
    t2 = seal_payload(payload, key).replace(b"0.99", b"1.0")
    try:
        open_payload(t2, key)
        check("tamper detected (fitness inflation)", False)
    except GenomeVaultError:
        check("tamper detected (fitness inflation)", True)

    # Wrong key rejected
    try:
        open_payload(blob, secrets.token_bytes(32))
        check("wrong key rejected", False)
    except GenomeVaultError:
        check("wrong key rejected", True)

    # Non-container garbage rejected
    for junk in (b"", b"pickled\x80\x04\x95evil", MAGIC):
        try:
            open_payload(junk, key)
            check(f"garbage rejected: {junk[:12]!r}", False)
        except GenomeVaultError:
            check(f"garbage rejected: {junk[:12]!r}", True)

    # Key file creation + reload
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        kp = os.path.join(td, "k", "genome_key.hex")
        k1 = load_key(kp)
        k2 = load_key(kp)
        check("key file persists", k1 == k2 and len(k1) == 32)

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILURES'}")
    return 1 if failures else 0


if __name__ == "__main__":
    # Bare invocation runs the self-test; the gate (tools/check.py) relies on
    # every security module being runnable with no arguments.
    if len(sys.argv) <= 1:
        sys.exit(_cli(["selftest"]))
    sys.exit(_cli(sys.argv[1:]))
