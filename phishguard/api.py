"""REST API and dashboard."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse

from . import config
from .ct import ct_source
from .enrich import RdapClient
from .pipeline import Pipeline
from .scorer import score_domain
from .sources import certstream_source, demo_source
from .store import Store

STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    source_name = config.source()
    store = Store(config.database_url())
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request is too noisy
    rdap = RdapClient() if config.enrich() else None
    pipeline = Pipeline(store, config.threshold(), source_name,
                        age_lookup=rdap.registered_on if rdap else None)
    app.state.store, app.state.pipeline = store, pipeline

    task = None
    if source_name == "demo":
        task = asyncio.create_task(pipeline.run(demo_source()))
    elif source_name == "ct":
        task = asyncio.create_task(pipeline.run(ct_source(config.ct_logs(), config.ct_tiled_logs())))
    elif source_name == "certstream":
        task = asyncio.create_task(pipeline.run(certstream_source(config.certstream_url())))
    yield
    if task:
        task.cancel()
    if rdap:
        await rdap.close()


app = FastAPI(
    title="PhishGuard",
    description="Real-time detection of domains impersonating protected brands.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/api/detections", summary="Latest suspicious domains, newest first")
def detections(
    request: Request,
    min_score: int = Query(0, ge=0, le=100),
    brand: str | None = Query(None, max_length=100),
    limit: int = Query(100, ge=1, le=500),
):
    return request.app.state.store.list(min_score, brand, limit)


@app.get("/api/check", summary="Score any domain on demand")
def check(domain: str = Query(..., min_length=1, max_length=253)):
    return asdict(score_domain(domain))


@app.get("/api/stats", summary="Pipeline and detection statistics")
def stats(request: Request):
    return {**request.app.state.pipeline.stats(), "detections": request.app.state.store.counts()}


@app.get("/api/brands", summary="Brands being protected")
def brands():
    return [{"name": b.name, "keywords": b.keywords, "official_domains": b.official_domains}
            for b in config.BRANDS]
