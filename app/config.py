"""Central configuration (environment variables with local-dev defaults)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    f = ROOT / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def _load_secrets() -> None:
    """Per-machine secrets live OUTSIDE the project (~/.dbmsel/secrets.env),
    created by scripts/_secrets.sh, so a zipped project never contains them."""
    f = Path(os.environ.get("DBMSEL_SECRETS_DIR", Path.home() / ".dbmsel")) / "secrets.env"
    if f.exists():
        for line in f.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_secrets()

PG_HOST = os.environ.get("PGHOST", "127.0.0.1")
PG_PORT = os.environ.get("PGPORT", "5433")
PG_DB = os.environ.get("PGDATABASE", "dbmsel")
DSN_APP = os.environ.get(
    "DSN_APP", f"postgresql://dbmsel_app:{os.environ.get('PG_APP_PASSWORD', '')}@{PG_HOST}:{PG_PORT}/{PG_DB}")
DSN_RO = os.environ.get(
    "DSN_RO", f"postgresql://dbmsel_ro:{os.environ.get('PG_RO_PASSWORD', '')}@{PG_HOST}:{PG_PORT}/{PG_DB}")

MONGO_URI = os.environ.get(
    "MONGO_URI", f"mongodb://dbmsel_app:{os.environ.get('MONGO_APP_PASSWORD', '')}@127.0.0.1:27018/dbmsel_raw"
                 "?authSource=dbmsel_raw")
MONGO_DB = os.environ.get("MONGO_DB", "dbmsel_raw")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "claude-opus-5-5")   # or claude-sonnet-5-5 / claude-haiku-5-5 (cheapest)
# auto | ollama | anthropic | none   (auto: anthropic if a key is set, else local Ollama if ready, else offline)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "auto").lower()
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))
# Google Gemini API (free key from https://aistudio.google.com). Put the key in
# ~/.dbmsel/secrets.env (outside the project) as GEMINI_API_KEY=...
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")

MODEL_DIR = ROOT / "models"
DATA_DIR = ROOT / "data"
# Real datasets live in data/raw/cicids2017 (CIC-IDS2017 MachineLearningCVE CSVs)
# and data/raw/ctu13/CTU-13-Dataset/*/ *.binetflow (CTU-13 NetFlow, text files only)

MAX_QUERY_ROWS = 500
ORG_TIMEZONE = "Asia/Kolkata"     # must match fn_org_timezone() in db/02_functions.sql
