"""Global domain-trust layer.

Three tiers decide how much scrutiny a URL's registered domain receives:

  curated  — hand-verified critical domains and restricted registries
             (config.TRUSTED_DOMAINS: banks, .bank.in/.gov.in spaces, …)
  popular  — among the registered domains of the world's 1M most-visited
             sites (Chrome UX Report), looked up in an offline Bloom filter
  unknown  — everything else: full heuristic scrutiny + "not a top-1M
             domain" signal (fresh phishing domains are never popular)

Registered domains are computed with the full Mozilla Public Suffix List
(exact + wildcard + exception rules), so the logic is correct for every
TLD — co.uk, com.au, bank.in, github.io pages, and so on.

Assets (built by scripts/build_trust_assets.py, shipped in phishguard/data/
and mirrored byte-for-byte in extension/model/ for the browser extension):
  psl.json          compiled Public Suffix List
  topdomains.bloom  Bloom filter (FNV-1a + djb2|1 double hashing, k=10)
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from phishguard import config

DATA_DIR = Path(__file__).resolve().parent / "data"
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# ------------------------------------------------------------------ PSL
@lru_cache(maxsize=1)
def _psl():
    psl = json.loads((DATA_DIR / "psl.json").read_text())
    return set(psl["r"]), set(psl["w"]), set(psl["e"])


def _public_suffix_labels(labels: list[str]) -> int:
    rules, wild, exc = _psl()
    n = len(labels)
    best = 0
    for i in range(n):
        cand = ".".join(labels[i:])
        if cand in exc:
            return n - i - 1
        if cand in rules and (n - i) > best:
            best = n - i
        if i + 1 < n and ".".join(labels[i + 1:]) in wild and (n - i) > best:
            best = n - i
    return best or 1


@lru_cache(maxsize=200_000)
def registered_domain(host: str) -> str:
    """PSL-correct registered domain for any hostname (IPs pass through)."""
    host = (host or "").lower().rstrip(".")
    if not host or _IP_RE.match(host):
        return host
    labels = host.split(".")
    ps_n = _public_suffix_labels(labels)
    if len(labels) <= ps_n:
        return host
    return ".".join(labels[-(ps_n + 1):])


# ------------------------------------------------------------------ Bloom
@lru_cache(maxsize=1)
def _bloom():
    blob = (DATA_DIR / "topdomains.bloom").read_bytes()
    assert blob[:4] == b"PGBF", "corrupt bloom filter"
    m = int.from_bytes(blob[4:8], "little")
    k = int.from_bytes(blob[8:12], "little")
    return m, k, blob[16:]


def _fnv1a(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = ((h * 33) + b) & 0xFFFFFFFF
    return h


def is_popular(reg_domain: str) -> bool:
    """O(1) membership test against the top-1M registered domains."""
    if not reg_domain:
        return False
    m, k, bitmap = _bloom()
    data = reg_domain.encode("ascii", "ignore")
    h1, h2 = _fnv1a(data), _djb2(data) | 1
    for i in range(k):
        idx = (h1 + i * h2) % m
        if not bitmap[idx >> 3] & (1 << (idx & 7)):
            return False
    return True


# ------------------------------------------------------------------ tiers
def trust_tier(reg_domain: str) -> str:
    """'curated' | 'popular' | 'unknown' for a registered domain."""
    if reg_domain in config.TRUSTED_DOMAINS or any(
            reg_domain.endswith("." + t) for t in config.TRUSTED_DOMAINS):
        return "curated"
    if is_popular(reg_domain):
        return "popular"
    return "unknown"
