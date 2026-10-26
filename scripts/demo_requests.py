"""Fire a stream of demo scans at a running PhishGuard server.

Great for the live demo: open the dashboard at http://localhost:8000,
run this script, and watch the live feed + charts update in real time.

Usage: python scripts/demo_requests.py [--host http://localhost:8000] [--delay 1.0]
"""
import argparse
import random
import time

import requests

PHISHY_URLS = [
    "http://paypal-secure.account-verify.tk/webscr/login?confirm=4852",
    "http://192.168.12.33/bank/login.php",
    "http://secure-login-apple.id-check.ml/verify",
    "http://www.amaz0n-prize-winner.xyz/claim?bonus=free",
    "http://bit.ly/3xFakeOffer",
    "http://netflix.billing-update.icu/account/suspend",
    "http://sbi-online.verify-kyc.top/login",
    "http://micros0ft-support.gq/unlock-account",
]
SAFE_URLS = [
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://www.google.com/search?q=weather",
    "https://github.com/topics/cybersecurity",
    "https://www.irctc.co.in/nget/train-search",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.microsoft.com/en-in/software-download",
]
PHISHY_EMAILS = [
    {"sender": "alert@secure-paypa1.gmail.com",
     "subject": "URGENT: Your account will be suspended in 24 hours",
     "body": "Dear customer, we detected unusual activity. Verify your "
             "password and billing information at http://192.168.4.21/verify "
             "immediately or lose access!!!"},
    {"sender": "lottery@winner-intl.com",
     "subject": "Congratulations! You won $2,500,000",
     "body": "Dear beneficiary, you have won the international lottery. "
             "Claim your cash prize now by sending your bank account details."},
    {"sender": "it-helpdesk@college-portal.tk",
     "subject": "Password expiry final notice",
     "body": "Your mailbox password expires today. Click http://10.1.1.5/reset "
             "to keep your account. Act now!"},
]
SAFE_EMAILS = [
    {"sender": "mentor@university.edu",
     "subject": "Project review moved to Thursday",
     "body": "Hi team, this week's review moves to Thursday 3 pm, same room. "
             "Bring the updated test results please."},
    {"sender": "library@college.edu",
     "subject": "Book return reminder",
     "body": "The book you borrowed is due this Friday. You can renew it "
             "once online if you still need it."},
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://localhost:8000")
    ap.add_argument("--delay", type=float, default=1.2)
    ap.add_argument("--rounds", type=int, default=20)
    args = ap.parse_args()

    for i in range(args.rounds):
        roll = random.random()
        if roll < 0.35:
            r = requests.post(f"{args.host}/api/scan/url",
                              json={"url": random.choice(PHISHY_URLS)})
        elif roll < 0.6:
            r = requests.post(f"{args.host}/api/scan/url",
                              json={"url": random.choice(SAFE_URLS)})
        elif roll < 0.8:
            r = requests.post(f"{args.host}/api/scan/email",
                              json=random.choice(PHISHY_EMAILS))
        else:
            r = requests.post(f"{args.host}/api/scan/email",
                              json=random.choice(SAFE_EMAILS))
        d = r.json()
        print(f"[{i+1:02d}] {d['type']:5s} {d['verdict']:10s} "
              f"risk={d['risk_score']:5.1f}  {d['input'][:60]}")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
