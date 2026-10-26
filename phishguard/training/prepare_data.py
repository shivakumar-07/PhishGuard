"""Stage 1 — Data collection & cleaning.

Builds the processed training tables from the raw public datasets:

* URLs   : faizann24 malicious-URL corpus (~420K labelled good/bad)
* Emails : phishing_pot (real-world phishing samples, CC-BY-4.0)
           + Enron spam/ham corpus (legitimate ham + deceptive spam)

Output (data/processed/):
    urls.parquet    columns: url, label           (1 = phishing/malicious)
    emails.parquet  columns: text, label          (1 = phishing/malicious)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from phishguard import config
from phishguard.features.email_features import clean_email_text

SPAM_SAMPLE = 8000  # Enron spam added to the malicious class (keeps classes balanced)


def prepare_urls() -> pd.DataFrame:
    df = pd.read_csv(config.URL_DATASET)
    df = df.rename(columns=str.lower)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len().between(4, 2048)]
    df = df.drop_duplicates(subset="url")
    df["label"] = (df["label"].str.lower() == "bad").astype("int8")
    df = df[["url", "label"]].reset_index(drop=True)
    print(f"[urls]   {len(df):,} rows | phishing={int(df.label.sum()):,} "
          f"({df.label.mean():.1%}) legitimate={int((1 - df.label).sum()):,}")
    return df


def prepare_emails() -> pd.DataFrame:
    # --- real phishing samples -------------------------------------------
    phish = pd.read_csv(config.PHISHTANK_EMAILS)
    phish["text"] = [
        clean_email_text(s, b) for s, b in zip(phish["subject"].fillna(""), phish["body"].fillna(""))
    ]
    phish = phish[phish["text"].str.len() > 10][["text"]]
    phish["label"] = 1

    # --- Enron ham (legitimate) + sampled spam (malicious) ---------------
    enron = pd.read_csv(config.ENRON_DATASET)
    enron["text"] = [
        clean_email_text(s, b)
        for s, b in zip(enron["Subject"].fillna(""), enron["Message"].fillna(""))
    ]
    enron = enron[enron["text"].str.len() > 10]

    ham = enron[enron["Spam/Ham"] == "ham"][["text"]].copy()
    ham["label"] = 0

    spam = enron[enron["Spam/Ham"] == "spam"][["text"]].sample(
        n=min(SPAM_SAMPLE, (enron["Spam/Ham"] == "spam").sum()),
        random_state=config.RANDOM_STATE,
    ).copy()
    spam["label"] = 1

    df = pd.concat([phish, spam, ham], ignore_index=True)
    df = df.drop_duplicates(subset="text").sample(frac=1.0, random_state=config.RANDOM_STATE)
    df = df.reset_index(drop=True)
    df["label"] = df["label"].astype("int8")
    print(f"[emails] {len(df):,} rows | malicious={int(df.label.sum()):,} "
          f"({df.label.mean():.1%}) legitimate={int((1 - df.label).sum()):,}")
    return df


def main() -> None:
    config.DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
    prepare_urls().to_parquet(config.DATA_PROCESSED / "urls.parquet", index=False)
    prepare_emails().to_parquet(config.DATA_PROCESSED / "emails.parquet", index=False)
    print("[done] processed datasets written to", config.DATA_PROCESSED)


if __name__ == "__main__":
    main()
