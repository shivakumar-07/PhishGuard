"""Download the public datasets PhishGuard trains on (Stage 1 helper).

Sources
-------
1. Malicious/benign URLs (~420K rows)
   https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs
2. Enron spam/ham email corpus (~33K emails)
   https://github.com/MWiechmann/enron_spam_data
3. phishing_pot — real-world phishing email samples (CC-BY-4.0, ~12K .eml)
   https://github.com/rf-peixoto/phishing_pot
   (large repo; this script downloads a pre-parsed CSV is NOT available
    upstream, so it clones shallowly and parses the .eml files itself)

Usage:  python setup_data.py            # downloads everything missing
        python setup_data.py --force    # re-download
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import shutil
import subprocess
import sys
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
URLS_DIR = ROOT / "data" / "raw" / "urls"
EMAILS_DIR = ROOT / "data" / "raw" / "emails"

URL_CSV = ("https://raw.githubusercontent.com/faizann24/"
           "Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv")
ENRON_ZIP = ("https://raw.githubusercontent.com/MWiechmann/"
             "enron_spam_data/master/enron_spam_data.zip")
PHISHING_POT = "https://github.com/rf-peixoto/phishing_pot.git"


def download(url: str, dest: Path) -> None:
    print(f"  downloading {url}")
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(r.content)
    print(f"  -> {dest} ({len(r.content)/1e6:.1f} MB)")


def strip_html(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def parse_eml(path: Path) -> tuple[str, str, str]:
    msg = BytesParser(policy=policy.default).parse(io.BytesIO(path.read_bytes()))
    subject = " ".join(str(msg.get("subject", "") or "").split())[:500]
    sender = " ".join(str(msg.get("from", "") or "").split())[:300]
    body = ""
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            body = part.get_content()
        else:
            part = msg.get_body(preferencelist=("html",))
            if part is not None:
                body = strip_html(part.get_content())
    except Exception:
        pass
    return subject, sender, " ".join(str(body).split())[:8000]


def build_phishing_pot_csv(out_csv: Path) -> None:
    tmp = ROOT / "data" / "raw" / "_phishing_pot_clone"
    if tmp.exists():
        shutil.rmtree(tmp)
    print("  cloning phishing_pot (shallow — a few hundred MB) ...")
    subprocess.run(["git", "clone", "--depth", "1", PHISHING_POT, str(tmp)],
                   check=True)
    n = 0
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["subject", "sender", "body", "label"])
        for eml in sorted((tmp / "email").glob("*.eml")):
            try:
                s, fr, b = parse_eml(eml)
                if s or b:
                    w.writerow([s, fr, b, "phishing"])
                    n += 1
            except Exception:
                continue
    shutil.rmtree(tmp)
    print(f"  -> {out_csv} ({n} phishing emails)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    print("[1/3] URL dataset")
    url_csv = URLS_DIR / "malicious_urls.csv"
    if args.force or not url_csv.exists():
        download(URL_CSV, url_csv)
    else:
        print("  already present")

    print("[2/3] Enron spam/ham corpus")
    enron_csv = EMAILS_DIR / "enron_spam_data.csv"
    if args.force or not enron_csv.exists():
        zip_path = EMAILS_DIR / "enron_spam_data.zip"
        download(ENRON_ZIP, zip_path)
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(EMAILS_DIR)
        zip_path.unlink()
        print(f"  -> {enron_csv}")
    else:
        print("  already present")

    print("[3/3] phishing_pot real phishing emails")
    pot_csv = EMAILS_DIR / "phishing_pot.csv"
    if args.force or not pot_csv.exists():
        build_phishing_pot_csv(pot_csv)
    else:
        print("  already present")

    print("\nAll datasets ready. Next:")
    print("  python phishguard/training/prepare_data.py")
    print("  python phishguard/training/train_url.py")
    print("  python phishguard/training/train_email.py")


if __name__ == "__main__":
    sys.exit(main())
