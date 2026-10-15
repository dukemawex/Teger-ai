"""Hardened fetch worker: the only process that opens connections to submitted destinations.

Run it as a separate service, ideally in its own container with network egress limited to
the public internet (no access to the API, databases, cloud metadata or private ranges):

    TEGER_FETCH_WORKER_TOKEN=<32+ random chars> uvicorn teger_investigator.worker:app --port 8200

The API calls it with :class:`teger_investigator.fetch.RemoteFetcher`. The worker never
receives customer cookies, credentials or tenant secrets — only a URL.
"""
from __future__ import annotations

import hmac
import os
import threading

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .fetch import IsolatedHttpFetcher

MAX_CONCURRENT = int(os.environ.get("TEGER_FETCH_WORKER_CONCURRENCY", "4"))


class FetchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=2048)


def create_worker(token: str | None = None, fetcher: IsolatedHttpFetcher | None = None,
                  max_concurrent: int = MAX_CONCURRENT) -> FastAPI:
    token = token if token is not None else os.environ.get("TEGER_FETCH_WORKER_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("TEGER_FETCH_WORKER_TOKEN must be at least 32 characters.")
    fetcher = fetcher or IsolatedHttpFetcher()
    slots = threading.BoundedSemaphore(max_concurrent)
    app = FastAPI(title="Teger fetch worker", docs_url=None, redoc_url=None, openapi_url=None)

    def authorize(authorization: str = Header(default="")) -> None:
        scheme, _, presented = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip(), token):
            raise HTTPException(401, "Unauthorized.")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/v1/fetch", dependencies=[Depends(authorize)])
    def fetch(body: FetchRequest):
        if not slots.acquire(blocking=False):
            raise HTTPException(429, "Fetch worker is busy.")
        try:
            chain = fetcher.fetch_chain(body.url)
        finally:
            slots.release()
        return {
            "hops": [{"url": h.url, "status": h.status, "location": h.location} for h in chain.hops],
            "final_url": chain.final_url, "final_status": chain.final_status, "content_type": chain.content_type,
            "body": chain.body, "truncated": chain.truncated, "error": chain.error, "error_kind": chain.error_kind,
        }

    return app


def _lazy_app() -> FastAPI:  # pragma: no cover - process entry point
    return create_worker()


def __getattr__(name: str):  # pragma: no cover - lets `uvicorn teger_investigator.worker:app` work
    if name == "app":
        return _lazy_app()
    raise AttributeError(name)
