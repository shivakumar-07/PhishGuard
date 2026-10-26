"""Central configuration for paths, thresholds and training parameters."""
from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT_DIR / "data" / "raw"
DATA_PROCESSED = ROOT_DIR / "data" / "processed"
MODELS_DIR = ROOT_DIR / "models"
RESULTS_DIR = ROOT_DIR / "results"
DB_PATH = ROOT_DIR / "data" / "phishguard.db"

URL_DATASET = DATA_RAW / "urls" / "malicious_urls.csv"
ENRON_DATASET = DATA_RAW / "emails" / "enron_spam_data.csv"
PHISHTANK_EMAILS = DATA_RAW / "emails" / "phishing_pot.csv"

URL_MODEL_PATH = MODELS_DIR / "url_ensemble.joblib"
EMAIL_MODEL_PATH = MODELS_DIR / "email_ensemble.joblib"
URL_METRICS_PATH = RESULTS_DIR / "url_metrics.json"
EMAIL_METRICS_PATH = RESULTS_DIR / "email_metrics.json"

# ---------------------------------------------------------------- training
RANDOM_STATE = 42
TEST_SIZE = 0.20
N_JOBS = -1

# ---------------------------------------------------------------- scoring
# Final risk score = ML_WEIGHT * ml_probability + HEURISTIC_WEIGHT * heuristic_score
ML_WEIGHT = 0.75
HEURISTIC_WEIGHT = 0.25

# verdict thresholds on the blended 0-100 risk score
THRESHOLD_PHISHING = 65.0
THRESHOLD_SUSPICIOUS = 40.0

# ---------------------------------------------------------------- misc
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com",
    "amazon.com", "wikipedia.org", "github.com", "linkedin.com", "twitter.com",
    "x.com", "instagram.com", "netflix.com", "office.com", "live.com",
    "yahoo.com", "paypal.com", "dropbox.com", "adobe.com", "zoom.us",
    "whatsapp.com", "telegram.org", "reddit.com", "stackoverflow.com",
    "mozilla.org", "cloudflare.com", "openai.com", "anthropic.com",
    "flipkart.com", "irctc.co.in", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "gov.in", "nic.in", "ac.in", "edu",
}
