"""Unit tests for the genome vault's tamper-evident container format.

These exercise the crypto/serialization core only (no `neat` dependency):
seal -> open round-trips, and every tamper class is rejected instead of
executed. That is the property that turned pickle.load() on an elevated
process into a refused load.
"""

import pytest

import genomevault as gv


@pytest.fixture()
def key():
    return bytes(range(32))


def test_seal_open_roundtrip(key):
    payload = {"genome": {"nodes": [1, 2], "conns": [[1, 2, 0.5]]},
               "config": "genome_config", "format": "test"}
    blob = gv.seal_payload(payload, key)
    assert blob.startswith(gv.MAGIC)
    assert gv.open_payload(blob, key) == payload


def test_canonical_json_is_deterministic(key):
    a = gv.canonical_json({"x": 1, "y": [2, 3]})
    b = gv.canonical_json({"y": [2, 3], "x": 1})
    assert a == b
    # and the seal is therefore byte-stable
    assert gv.seal_payload({"x": 1}, key) == gv.seal_payload({"x": 1}, key)


def test_tampered_body_rejected(key):
    blob = bytearray(gv.seal_payload({"w": [0.1, 0.2]}, key))
    # flip one bit in the weights
    blob[len(gv.MAGIC) + 10] ^= 0x01
    with pytest.raises(gv.GenomeVaultError):
        gv.open_payload(bytes(blob), key)


def test_inflated_fitness_rejected(key):
    blob = bytearray(gv.seal_payload({"fitness": 0.5}, key))
    idx = len(gv.MAGIC) + blob.find(b"0.5")
    assert idx >= len(gv.MAGIC)
    blob[idx] ^= 0x01  # 0.5 -> 1.5 or q.5: either way the tag no longer fits
    with pytest.raises(gv.GenomeVaultError):
        gv.open_payload(bytes(blob), key)


def test_wrong_key_rejected(key):
    blob = gv.seal_payload({"a": 1}, key)
    with pytest.raises(gv.GenomeVaultError):
        gv.open_payload(blob, bytes(range(32, 64)))


def test_raw_pickle_garbage_rejected(key):
    # The whole point: a legacy/malicious pickle blob is NOT a container and
    # must never reach a deserializer.
    with pytest.raises(gv.GenomeVaultError):
        gv.open_payload(b"\x80\x04\x95cos\nsystem", key)


def test_truncated_container_rejected(key):
    blob = gv.seal_payload({"a": 1}, key)
    with pytest.raises(gv.GenomeVaultError):
        gv.open_payload(blob[: len(blob) // 2], key)
    with pytest.raises(gv.GenomeVaultError):
        gv.open_payload(b"", key)


def test_holds_up_against_bitflips_anywhere(key):
    import itertools
    blob = gv.seal_payload({"conns": [[1, 2, 0.735]], "nodes": [0, 1]}, key)
    damaged = 0
    for offset in range(len(gv.MAGIC), len(blob), max(1, len(blob) // 40)):
        bad = bytearray(blob)
        bad[offset] ^= 0xFF
        try:
            gv.open_payload(bytes(bad), key)
        except gv.GenomeVaultError:
            damaged += 1
    assert damaged > 0, "no corruption was detected -- verifier is broken"
