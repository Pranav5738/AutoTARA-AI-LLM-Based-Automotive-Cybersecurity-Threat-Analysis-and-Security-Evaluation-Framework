from __future__ import annotations

import json
import os
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from evaluator import DEFAULT_TIMEOUT_SEC, generate_report, run_one
from model_client import create_model_client
from yaml_loader import get_all_prompts, get_prompt_by_id, get_prompts_by_suite, load_test_suites

load_dotenv()

ROOT = Path(__file__).parent
YAML_PATH = ROOT / "tests" / "test_suites.yaml"
STATIC_PATH = ROOT / "frontend"
DATABASE_URL = os.getenv("DATABASE_URL", "")
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(ROOT / "results" / "runs.db")))
MAX_CONCURRENT_RUNS = int(os.getenv("MAX_CONCURRENT_RUNS", "1"))
MAX_RUNS_PER_MINUTE = int(os.getenv("MAX_RUNS_PER_MINUTE", "3"))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_RUNS)
recent_runs: list[float] = []
app = FastAPI(title="AutoTARA Security Evaluation API", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")


class RunRequest(BaseModel):
    provider: str = Field(default_factory=lambda: os.getenv("MODEL_PROVIDER", "gemini"))
    model: str = Field(default_factory=lambda: os.getenv("MODEL_NAME", "gemini-3.8-flash"))
    suite: str | None = None
    test_case_id: str | None = None
    timeout: int = Field(default=DEFAULT_TIMEOUT_SEC, ge=10, le=600)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_connection() -> Any:
    if DATABASE_URL:
        import psycopg
        return psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


def sql_query(query: str) -> str:
    return query.replace("?", "%s") if DATABASE_URL else query


def execute(query: str, params: tuple[Any, ...] = ()) -> None:
    with db_connection() as db:
        db.execute(sql_query(query), params)
        db.commit()


def fetch_one(query: str, params: tuple[Any, ...] = ()) -> Any:
    with db_connection() as db:
        return db.execute(sql_query(query), params).fetchone()


def fetch_all(query: str, params: tuple[Any, ...] = ()) -> list[Any]:
    with db_connection() as db:
        return db.execute(sql_query(query), params).fetchall()


def init_database() -> None:
    with db_connection() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                filter_desc TEXT NOT NULL,
                request_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                completed_at TEXT,
                report TEXT,
                results_json TEXT,
                error TEXT
            )
            """
        )
        if not DATABASE_URL:
            columns = {row[1] for row in db.execute("PRAGMA table_info(runs)").fetchall()}
            if "request_json" not in columns:
                db.execute("ALTER TABLE runs ADD COLUMN request_json TEXT NOT NULL DEFAULT '{}'")
        else:
            db.execute(
                """
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS
                request_json TEXT NOT NULL DEFAULT '{}'
                """
            )
        db.execute(
            sql_query(
                "UPDATE runs SET status='queued', error=NULL "
                "WHERE status='running' AND completed_at IS NULL"
            )
        )
        db.commit()


def enforce_rate_limit() -> None:
    current = datetime.now(timezone.utc).timestamp()
    recent_runs[:] = [stamp for stamp in recent_runs if current - stamp < 60]
    if len(recent_runs) >= MAX_RUNS_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Run rate limit exceeded; try again later")
    recent_runs.append(current)


def select_prompts(request: RunRequest) -> tuple[list[Any], str]:
    if request.test_case_id:
        return [get_prompt_by_id(YAML_PATH, request.test_case_id)], f"case={request.test_case_id}"
    if request.suite:
        return get_prompts_by_suite(YAML_PATH, request.suite), f"suite={request.suite}"
    return get_all_prompts(YAML_PATH), "all suites"


def run_job(run_id: str, request: RunRequest) -> None:
    try:
        execute("UPDATE runs SET status=? WHERE id=?", ("running", run_id))
        prompts, filter_desc = select_prompts(request)
        client = create_model_client(request.provider, request.model, request.timeout)
        run_results = [
            run_one(prompt, request.model, request.timeout, client=client)
            for prompt in prompts
        ]
        report = generate_report(run_results, request.model, filter_desc)
        serializable = [
            {"result": item["result"].to_dict(), "duration_ms": item["duration_ms"], "error": item["error"]}
            for item in run_results
        ]
        execute(
            "UPDATE runs SET status=?, completed_at=?, report=?, results_json=? WHERE id=?",
            ("completed", now(), report, json.dumps(serializable), run_id),
        )
    except Exception as exc:
        execute(
            "UPDATE runs SET status=?, completed_at=?, error=? WHERE id=?",
            ("failed", now(), str(exc), run_id),
        )


def resume_queued_runs() -> None:
    for row in fetch_all(
        "SELECT id, request_json FROM runs WHERE status='queued' ORDER BY created_at ASC LIMIT 20"
    ):
        executor.submit(run_job, row["id"], RunRequest(**json.loads(row["request_json"])))


@app.on_event("startup")
def startup() -> None:
    init_database()
    resume_queued_runs()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_PATH / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    try:
        fetch_one("SELECT 1")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {exc}") from exc
    return {"status": "ok", "service": "autotara"}


@app.get("/api/options")
def options() -> dict[str, Any]:
    suites = load_test_suites(YAML_PATH).test_suites
    cases = [case for suite in suites for case in suite.cases]
    return {
        "providers": ["gemini", "ollama"],
        "default_provider": os.getenv("MODEL_PROVIDER", "gemini"),
        "default_model": os.getenv("MODEL_NAME", "gemini-3.8-flash"),
        "suites": [{"id": suite.id, "name": suite.name} for suite in suites],
        "cases": [{"id": case.id, "name": case.name, "risk_level": case.risk_level.value} for case in cases],
    }


@app.post("/api/runs")
def create_run(request: RunRequest) -> dict[str, str]:
    enforce_rate_limit()
    try:
        prompts, filter_desc = select_prompts(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not prompts:
        raise HTTPException(status_code=400, detail="No test cases selected")
    run_id = uuid.uuid4().hex
    execute(
        "INSERT INTO runs (id,status,provider,model,filter_desc,request_json,created_at) VALUES (?,?,?,?,?,?,?)",
        (run_id, "queued", request.provider, request.model, filter_desc, request.model_dump_json(), now()),
    )
    executor.submit(run_job, run_id, request)
    return {"id": run_id, "status": "queued"}


@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    rows = fetch_all(
        "SELECT id,status,provider,model,filter_desc,created_at,completed_at,error "
        "FROM runs ORDER BY created_at DESC LIMIT 50"
    )
    return [dict(row) for row in rows]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    row = fetch_one("SELECT * FROM runs WHERE id=?", (run_id,))
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")
    result = dict(row)
    result["results"] = json.loads(result.pop("results_json") or "[]")
    result.pop("report", None)
    result.pop("request_json", None)
    return result


@app.get("/api/runs/{run_id}/report")
def get_report(run_id: str) -> PlainTextResponse:
    row = fetch_one("SELECT report FROM runs WHERE id=?", (run_id,))
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return PlainTextResponse(row["report"] or "Report is not ready")
