"""Trusted control plane: health, run ledger, and static report files.

This process never executes agent commands. Celesto computers are created by the
agent runner through the Celesto SDK/CLI; this API only records what happened.
"""
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://ledger:ledger@ledger:5432/ledger")
NAME_RE = re.compile(r"^sbx-[a-z0-9]{8,}$")
STATES = {"created", "ready", "running", "succeeded", "failed", "deleted"}
TARGET = "celesto_sandbox"

DDL = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  sandbox_name TEXT NOT NULL,
  problem_id TEXT NOT NULL,
  state TEXT NOT NULL,
  execution_target TEXT NOT NULL DEFAULT 'celesto_sandbox',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

UPSERT = """
INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (run_id) DO UPDATE
  SET sandbox_name = EXCLUDED.sandbox_name,
      problem_id = EXCLUDED.problem_id,
      state = EXCLUDED.state,
      execution_target = EXCLUDED.execution_target
RETURNING run_id, sandbox_name, problem_id, state, execution_target
"""


def connect(retries: int = 30):
    last = None
    for _ in range(retries):
        try:
            return psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=True)
        except psycopg.OperationalError as exc:
            last = exc
            time.sleep(1)
    raise RuntimeError(f"ledger unreachable: {last}")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    with connect() as conn:
        conn.execute(DDL)
    yield


app = FastAPI(title="Run Ledger", lifespan=lifespan)


def validate(body) -> str | None:
    if not isinstance(body, dict):
        return "body must be a JSON object"
    for key in ("run_id", "sandbox_name", "problem_id", "state", "execution_target"):
        if not isinstance(body.get(key), str) or not body[key].strip():
            return f"{key} must be a non-empty string"
    if not NAME_RE.match(body["sandbox_name"]):
        return "sandbox_name must match sbx- plus 8+ lowercase letters or digits"
    if body["state"] not in STATES:
        return f"state must be one of {sorted(STATES)}"
    if body["execution_target"] != TARGET:
        return f"execution_target must be {TARGET}"
    return None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/runs")
def list_runs():
    with connect() as conn:
        rows = conn.execute(
            "SELECT run_id, sandbox_name, problem_id, state, execution_target, created_at "
            "FROM runs ORDER BY created_at, run_id"
        ).fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat()
    return rows


@app.post("/api/runs", status_code=201)
async def create_run(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    err = validate(body)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    with connect() as conn:
        row = conn.execute(
            UPSERT,
            (body["run_id"], body["sandbox_name"], body["problem_id"], body["state"], body["execution_target"]),
        ).fetchone()
    return JSONResponse(row, status_code=201)


# Serve already-produced evidence even when no KVM / cloud key is available.
for mount, folder in (("/reports", "reports"), ("/logs", "logs")):
    if Path(folder).is_dir():
        app.mount(mount, StaticFiles(directory=folder), name=folder)
