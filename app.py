"""
app.py — SENTRY AI Defense Console backend
-------------------------------------------------------------------
FastAPI-applicatie die:
  1. Het statische dashboard serveert (index.html + script.js).
  2. Een echte /api/scan-prompt endpoint aanbiedt die de
     prompt_firewall.py regelset toepast (server-side enforcement,
     niet alleen client-side preview).
  3. Een echt /api/honeypot-hit endpoint dat honeypot-triggers
     logt (voor gebruik door externe formulieren/integraties).
  4. Een echte token-bucket rate limiter als ASGI-middleware,
     zodat álle endpoints hieronder vallen.
  5. /api/health voor systemd/nginx health-checks.

Draai lokaal:
    uvicorn app:app --host 127.0.0.1 --port 8000 --reload

In productie (zie deploy/ai-defense.service):
    uvicorn wordt aangeroepen via de venv, achter nginx als reverse
    proxy op botnet.abelsoftware123.com.
-------------------------------------------------------------------
"""

from __future__ import annotations

import sys
import time
import logging
from pathlib import Path
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# server-middleware/prompt_firewall.py hergebruiken i.p.v. dupliceren
sys.path.append(str(Path(__file__).resolve().parent.parent / "server-middleware"))
from prompt_firewall import scan_prompt  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("sentry")

BASE_DIR = Path(__file__).resolve().parent.parent  # project root, waar index.html staat

app = FastAPI(title="SENTRY AI Defense Console", version="1.0.0")


# =====================================================================
# Token-bucket rate limiter — ASGI middleware, geldt voor alle routes.
# Zelfde algoritme als server-middleware/rate_limiter.js, hier in
# Python zodat de FastAPI-backend zelfstandig draait zonder Node.
# =====================================================================

class TokenBucket:
    __slots__ = ("tokens", "last_refill")

    def __init__(self, capacity: float):
        self.tokens = capacity
        self.last_refill = time.monotonic()


class RateLimiterState:
    def __init__(self, capacity: int = 30, refill_rate: float = 5.0):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per seconde
        self.buckets: dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(capacity))

    def consume(self, key: str) -> tuple[bool, float, float]:
        bucket = self.buckets[key]
        now = time.monotonic()
        elapsed = now - bucket.last_refill
        bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
        bucket.last_refill = now

        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True, bucket.tokens, 0.0

        retry_after = max(1.0, (1 - bucket.tokens) / self.refill_rate)
        return False, bucket.tokens, retry_after


rate_limiter_state = RateLimiterState(capacity=30, refill_rate=5.0)


# =====================================================================
# Gecombineerde trust-scoring — Python-equivalent van
# server-middleware/trust_engine.js. Combineert signalen i.p.v. ze
# los te laten blokkeren, zodat een aanvaller elk signaal apart moet
# omzeilen om onder de drempel te blijven.
# =====================================================================

KNOWN_SCRAPER_UA_PATTERNS = [
    "python-requests", "scrapy", "curl/", "wget", "go-http-client",
    "headlesschrome", "phantomjs",
]

TRUST_WEIGHTS = {
    "scraper_user_agent": -25,
    "missing_accept_language": -10,
    "missing_accept": -10,
    "rate_limit_hit": -15,
    "clean_request_reward": 1,
}

MIN_TRUST_TO_ALLOW = 30


class TrustRecord:
    __slots__ = ("score", "last_seen")

    def __init__(self):
        self.score = 100.0
        self.last_seen = time.time()


trust_records: dict[str, TrustRecord] = defaultdict(TrustRecord)


def adjust_trust(key: str, delta: float) -> float:
    record = trust_records[key]
    record.score = max(0.0, min(100.0, record.score + delta))
    record.last_seen = time.time()
    return record.score


def evaluate_trust(request: Request) -> dict:
    """Combineert user-agent-, header- en rate-limit-signalen tot één
    score. Client-gerapporteerde signalen (mouse-entropy uit script.js)
    worden BEWUST niet hier meegenomen als positief bewijs — een client
    kan altijd liegen dat hij menselijk is. Alleen server-waarneembare
    signalen tellen mee voor de score."""
    key = request.client.host if request.client else "unknown"
    ua = (request.headers.get("user-agent") or "").lower()
    reasons = []

    if any(p in ua for p in KNOWN_SCRAPER_UA_PATTERNS) or ua == "":
        adjust_trust(key, TRUST_WEIGHTS["scraper_user_agent"])
        reasons.append("scraper_user_agent")

    if not request.headers.get("accept-language"):
        adjust_trust(key, TRUST_WEIGHTS["missing_accept_language"])
        reasons.append("missing_accept_language")

    if not request.headers.get("accept"):
        adjust_trust(key, TRUST_WEIGHTS["missing_accept"])
        reasons.append("missing_accept")

    if not reasons:
        adjust_trust(key, TRUST_WEIGHTS["clean_request_reward"])

    score = trust_records[key].score
    return {"key": key, "score": score, "reasons": reasons}


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Statische bestanden (dashboard zelf) niet meetellen tegen de API-limiet,
    # anders blokkeer je jezelf al bij het simpelweg laden van de pagina.
    if request.url.path.startswith("/api/"):
        client_key = request.client.host if request.client else "unknown"
        allowed, remaining, retry_after = rate_limiter_state.consume(client_key)

        if not allowed:
            adjust_trust(client_key, TRUST_WEIGHTS["rate_limit_hit"])
            logger.warning("rate limit hit: %s on %s", client_key, request.url.path)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "too_many_requests",
                    "message": f"Rate limit overschreden. Probeer over {retry_after:.1f}s opnieuw.",
                    "retry_after_seconds": round(retry_after, 1),
                },
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_limiter_state.capacity)
        response.headers["X-RateLimit-Remaining"] = str(int(remaining))
        return response

    return await call_next(request)


# =====================================================================
# API-modellen
# =====================================================================

class ScanRequest(BaseModel):
    message: str


class HoneypotHit(BaseModel):
    field: str = "website_url"
    value: str
    user_agent: str | None = None
    path: str | None = None


# In-memory logs — voor productie vervang je dit door een echte database.
honeypot_log: list[dict] = []


# =====================================================================
# API-routes
# =====================================================================

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "sentry-ai-defense", "time": time.time()}


@app.post("/api/scan-prompt")
async def api_scan_prompt(payload: ScanRequest):
    """Server-side enforcement van de prompt-injectie firewall.
    Dit is de bron van waarheid — gebruik dit endpoint (of importeer
    prompt_firewall.scan_prompt direct) vóórdat je user-input naar
    een eigen LLM doorstuurt."""
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="message mag niet leeg zijn")

    result = scan_prompt(payload.message)
    logger.info("prompt scan verdict=%s score=%s", result.verdict, result.score)
    return result.as_dict()


@app.post("/api/honeypot-hit")
async def api_honeypot_hit(hit: HoneypotHit, request: Request):
    """Endpoint waar formulieren/integraties honeypot-triggers naartoe
    kunnen sturen. Elke hit hier is per definitie van een geautomatiseerd
    systeem — een mens ziet en vult dit veld nooit in."""
    client_ip = request.client.host if request.client else "unknown"
    entry = {
        "ip": client_ip,
        "field": hit.field,
        "value": hit.value,
        "user_agent": hit.user_agent or request.headers.get("user-agent"),
        "path": hit.path,
        "time": time.time(),
    }
    honeypot_log.append(entry)
    logger.warning("honeypot hit: %s", entry)
    return {"status": "logged"}


@app.get("/api/honeypot-log")
async def api_honeypot_log():
    """Laatste 100 honeypot-hits, nieuwste eerst."""
    return {"hits": list(reversed(honeypot_log[-100:]))}


@app.get("/api/trust-score")
async def api_trust_score(request: Request):
    """Geeft de gecombineerde trust-score van de aanroepende client
    terug, opgebouwd uit alle server-observeerbare signalen tot nu toe
    (user-agent, headers, rate-limit-geschiedenis). Nuttig om vanuit
    andere routes/services te controleren of een client onder de
    drempel is gezakt vóór je een dure operatie uitvoert."""
    result = evaluate_trust(request)
    allowed = result["score"] >= MIN_TRUST_TO_ALLOW
    return {**result, "allowed": allowed, "threshold": MIN_TRUST_TO_ALLOW}


# =====================================================================
# Static files — het dashboard zelf (index.html + script.js)
# Gemount ná de /api/-routes zodat die voorrang krijgen.
# =====================================================================

@app.get("/")
async def serve_index():
    index_path = BASE_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html niet gevonden")
    return FileResponse(index_path)


app.mount("/", StaticFiles(directory=str(BASE_DIR)), name="static")
