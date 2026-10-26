"""Stage 5 — FastAPI backend: REST API + WebSocket live feed + dashboard.

Run with:  uvicorn phishguard.api.main:app --reload
      or:  python -m phishguard.api.main
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishguard import config, __version__
from phishguard.api import db
from phishguard.inference import predictor

app = FastAPI(
    title="PhishGuard API",
    version=__version__,
    description="AI-powered phishing detection for URLs & emails — hybrid "
                "ML ensemble + heuristic rule layer with real-time dashboard.",
)

STATIC_DIR = Path(__file__).parent / "static"


# ------------------------------------------------------------------ schemas
class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048,
                     examples=["http://paypal-verify.account-update.tk/login"])


class EmailScanRequest(BaseModel):
    subject: str = Field("", max_length=500)
    body: str = Field(..., min_length=1, max_length=50_000)
    sender: str = Field("", max_length=300)


# ------------------------------------------------------------------ live feed
class LiveFeed:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        message = json.dumps(payload)
        dead = []
        for ws in self.clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


feed = LiveFeed()


# ------------------------------------------------------------------ routes
@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": __version__,
            "models": predictor.models_ready()}


@app.post("/api/scan/url")
async def scan_url(req: UrlScanRequest) -> dict:
    try:
        result = await asyncio.to_thread(predictor.predict_url, req.url)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    result["id"] = db.insert_scan(result)
    await feed.broadcast({"event": "scan", "data": _feed_row(result)})
    return result


@app.post("/api/scan/email")
async def scan_email(req: EmailScanRequest) -> dict:
    try:
        result = await asyncio.to_thread(
            predictor.predict_email, req.subject, req.body, req.sender)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    result["id"] = db.insert_scan(result)
    await feed.broadcast({"event": "scan", "data": _feed_row(result)})
    return result


@app.get("/api/scans")
async def scans(limit: int = 50) -> list[dict]:
    return db.recent_scans(min(max(limit, 1), 500))


@app.get("/api/stats")
async def stats() -> dict:
    return db.stats()


@app.get("/api/model-info")
async def model_info() -> dict:
    out = {}
    for name, path in (("url", config.URL_METRICS_PATH),
                       ("email", config.EMAIL_METRICS_PATH)):
        if path.exists():
            out[name] = json.loads(path.read_text())
    out["thresholds"] = {"phishing": config.THRESHOLD_PHISHING,
                         "suspicious": config.THRESHOLD_SUSPICIOUS,
                         "ml_weight": config.ML_WEIGHT,
                         "heuristic_weight": config.HEURISTIC_WEIGHT}
    return out


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket) -> None:
    await feed.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive pings from the client
    except WebSocketDisconnect:
        feed.disconnect(ws)


def _feed_row(result: dict) -> dict:
    return {"id": result.get("id"), "scan_type": result["type"],
            "input_text": result["input"][:120], "verdict": result["verdict"],
            "risk_score": result["risk_score"],
            "ml_prob": result["ml_probability"],
            "heur_score": result["heuristic_score"]}


# ------------------------------------------------------------------ dashboard
@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("phishguard.api.main:app", host="0.0.0.0", port=8000)
