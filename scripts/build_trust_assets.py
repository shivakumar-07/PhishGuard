"""Compile the global domain-trust assets PhishGuard ships with.

Inputs (downloaded if not supplied):
  1. Mozilla Public Suffix List  -> psl.json   (exact / wildcard / exception
     rules, so "registered domain" is computed correctly for every TLD)
  2. Chrome UX Report global top-1M origins -> topdomains.bloom
     (registered domains of the 1M most-visited sites, packed into a Bloom
     filter for O(1), offline, ~1.5 MB reputation lookup)

Bloom format (little-endian):  b"PGBF" | uint32 m_bits | uint32 k | uint32 n
followed by ceil(m/8) bitmap bytes. Hashing is FNV-1a 32-bit + (djb2|1)
with Kirsch-Mitzenmacher double hashing — implemented identically in
phishguard/trust.py and extension/lib/engine.js.

Usage:
  python scripts/build_trust_assets.py [--psl FILE] [--crux FILE.csv.gz]
"""
from __future__ import annotations

import argparse
import gzip
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PSL_URL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"

OUT_DIRS = [ROOT / "phishguard" / "data", ROOT / "extension" / "model"]
TARGET_FP = 0.001  # Bloom false-positive rate


# ------------------------------------------------------------------ PSL
def compile_psl(path: Path) -> dict:
    rules, wild, exc = [], [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exc.append(line[1:])
        elif line.startswith("*."):
            wild.append(line[2:])
        else:
            rules.append(line)
    print(f"[psl] {len(rules)} exact, {len(wild)} wildcard, {len(exc)} exception rules")
    return {"r": rules, "w": wild, "e": exc}


def make_psl_lookup(psl: dict):
    rules, wild, exc = set(psl["r"]), set(psl["w"]), set(psl["e"])

    def public_suffix_labels(labels):
        n = len(labels)
        best = 0
        for i in range(n):
            cand = ".".join(labels[i:])
            if cand in exc:
                return n - i - 1  # exception prevails: suffix minus first label
            if cand in rules and (n - i) > best:
                best = n - i
            if i + 1 < n and ".".join(labels[i + 1:]) in wild and (n - i) > best:
                best = n - i
        return best or 1  # default rule "*"

    def registered_domain(host: str) -> str:
        host = (host or "").lower().rstrip(".")
        if not host or host.replace(".", "").isdigit():
            return host
        labels = host.split(".")
        ps_n = public_suffix_labels(labels)
        if len(labels) <= ps_n:
            return host
        return ".".join(labels[-(ps_n + 1):])

    return registered_domain


# ------------------------------------------------------------------ Bloom
def fnv1a(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = ((h * 33) + b) & 0xFFFFFFFF
    return h


def build_bloom(domains: set[str], fp: float) -> bytes:
    n = len(domains)
    m = math.ceil(n * math.log(1 / fp) / (math.log(2) ** 2))
    m = (m + 7) // 8 * 8
    k = max(1, round(m / n * math.log(2)))
    bitmap = bytearray(m // 8)
    for d in domains:
        data = d.encode("ascii", "ignore")
        h1 = fnv1a(data)
        h2 = djb2(data) | 1
        for i in range(k):
            idx = (h1 + i * h2) % m
            bitmap[idx >> 3] |= 1 << (idx & 7)
    header = b"PGBF" + m.to_bytes(4, "little") + k.to_bytes(4, "little") + n.to_bytes(4, "little")
    print(f"[bloom] n={n:,} domains  m={m:,} bits ({m // 8 / 1e6:.2f} MB)  k={k}  target fp={fp}")
    return bytes(header) + bytes(bitmap)


def bloom_has(blob: bytes, domain: str) -> bool:
    m = int.from_bytes(blob[4:8], "little")
    k = int.from_bytes(blob[8:12], "little")
    bitmap = blob[16:]
    data = domain.encode("ascii", "ignore")
    h1, h2 = fnv1a(data), djb2(data) | 1
    return all(bitmap[((h1 + i * h2) % m) >> 3] & (1 << (((h1 + i * h2) % m) & 7))
               for i in range(k))


# ------------------------------------------------------------------ main
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--psl", type=Path, default=None)
    ap.add_argument("--crux", type=Path, default=None)
    args = ap.parse_args()

    psl_path, crux_path = args.psl, args.crux
    if psl_path is None or crux_path is None:
        import requests
        tmp = ROOT / "data" / "raw" / "trust"
        tmp.mkdir(parents=True, exist_ok=True)
        if psl_path is None:
            psl_path = tmp / "public_suffix_list.dat"
            if not psl_path.exists():
                psl_path.write_bytes(requests.get(PSL_URL, timeout=120).content)
        if crux_path is None:
            crux_path = tmp / "crux.csv.gz"
            if not crux_path.exists():
                crux_path.write_bytes(requests.get(CRUX_URL, timeout=300).content)

    psl = compile_psl(psl_path)
    reg_of = make_psl_lookup(psl)

    domains: set[str] = set()
    with gzip.open(crux_path, "rt", encoding="utf-8", errors="ignore") as f:
        next(f)  # header
        for line in f:
            origin = line.split(",", 1)[0].strip()
            host = origin.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            reg = reg_of(host)
            if reg and "." in reg:
                domains.add(reg)
    print(f"[crux] 1M origins -> {len(domains):,} unique registered domains")

    blob = build_bloom(domains, TARGET_FP)

    # sanity: members hit, random misses stay out
    assert bloom_has(blob, "google.com") and bloom_has(blob, "wikipedia.org")
    assert not bloom_has(blob, "paypal-secure-verify-account-x9.tk")

    psl_json = json.dumps(psl, separators=(",", ":"))
    for out in OUT_DIRS:
        out.mkdir(parents=True, exist_ok=True)
        (out / "psl.json").write_text(psl_json)
        (out / "topdomains.bloom").write_bytes(blob)
        print(f"[write] {out}/psl.json ({len(psl_json)/1e6:.2f} MB), "
              f"topdomains.bloom ({len(blob)/1e6:.2f} MB)")


if __name__ == "__main__":
    main()
