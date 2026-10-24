# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Separate read-only owner dashboard. No cloud client is created at import."""
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from ui.app import cached_snapshot, defensive_headers

app = FastAPI(title="Remediation Zero dashboard", docs_url=None, redoc_url=None,
              openapi_url=None)
app.middleware("http")(defensive_headers)
from ui.dashboard_view import VIEWS, demo_snapshot, recent_decisions, render


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    view = request.query_params.get("view", "overview")
    if view not in VIEWS:
        return HTMLResponse("View not found", status_code=404)
    demo = os.environ.get("RZ_DASHBOARD_DEMO") == "1"
    try:
        data = demo_snapshot() if demo else cached_snapshot()
    except Exception:
        return HTMLResponse(render({}, view, unavailable=True), status_code=503,
                            headers={"Cache-Control": "no-store"})
    return HTMLResponse(render(data, view, demo=demo), headers={"Cache-Control": "no-store"})
