"""Read-only local API and event stream for Sentinel telemetry."""

import asyncio
import json
import os
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from telemetry_store import TelemetryStore


@lru_cache(maxsize=1)
def _default_store():
    path = os.environ.get(
        "SENTINEL_DATABASE_FILE",
        os.path.expanduser("~/.sentinel.db"),
    )
    return TelemetryStore(path)


def create_app(store=None):
    app = FastAPI(
        title="Sentinel Telemetry API",
        description="Read-only event, incident, and ingestion-health endpoints.",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    telemetry = store or _default_store

    def get_store():
        return telemetry() if callable(telemetry) else telemetry

    @app.get("/", include_in_schema=False)
    def root():
        return {
            "service": "Sentinel Telemetry API",
            "interface": "terminal",
            "health": "/api/health",
        }

    @app.get("/api/health")
    def health():
        return get_store().health()

    @app.get("/api/events")
    def events(
        limit: int = Query(default=100, ge=1, le=5000),
        since: str | None = None,
    ):
        return get_store().recent_events(limit=limit, since=since)

    @app.get("/api/incidents")
    def incidents(
        limit: int = Query(default=100, ge=1, le=1000),
        status: str | None = Query(default=None, pattern="^(open|closed)$"),
    ):
        return get_store().list_incidents(limit=limit, status=status)

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str):
        result = get_store().get_incident(incident_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return result

    @app.get("/api/stream")
    async def stream(
        request: Request,
        after_id: int = Query(default=0, ge=0),
    ):
        async def generate():
            cursor = after_id
            while not await request.is_disconnected():
                rows = get_store().events_after(cursor, limit=500)
                if rows:
                    for row in rows:
                        cursor = row["id"]
                        yield (
                            f"id: {cursor}\n"
                            f"event: telemetry\n"
                            f"data: {json.dumps(row['event'], separators=(',', ':'), default=str)}\n\n"
                        )
                else:
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(1)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return app


app = create_app()
