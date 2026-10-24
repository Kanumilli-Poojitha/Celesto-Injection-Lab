"""Mirrors the grader's file checks. Run: pytest -q  (fails until real reports exist)."""
import json
import math
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"^sbx-[a-z0-9]{8,}$")
CAPS = {"persistence", "snapshots", "celestofs", "browser", "published_ports",
        "network_policy", "safety_hooks", "host_mounts", "coding_agent_preset", "agentor_durable"}


def load(rel):
    return json.loads((ROOT / rel).read_text())


def jsonl(rel):
    return [json.loads(l) for l in (ROOT / rel).read_text().splitlines() if l.strip()]


def test_compose():
    s = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    assert {"api", "ledger"} <= set(s)
    for n in ("api", "ledger"):
        assert all(k in s[n]["healthcheck"] for k in ("interval", "timeout", "retries", "start_period"))
    assert any("seeds" in v for v in s["ledger"]["volumes"])
    assert s["api"]["depends_on"]["ledger"]["condition"] == "service_healthy"


def test_env():
    assert not (ROOT / ".env").exists()
    text = (ROOT / ".env.example").read_text()
    for k in ("CELESTO_PROVIDER", "CELESTO_API_KEY", "LLM_API_KEY", "LLM_MODEL", "DATABASE_URL", "API_PORT"):
        assert re.search(rf"^{k}=", text, re.M), k


def test_problem():
    p = load("reports/problem.json")
    assert len(p["who"]) >= 40 and len(p["agent_work"]) >= 40 and len(p["proof_output"]) >= 20
    assert p["idea_source"] in {"idea_bank", "original"}


def test_commands_log():
    rows = jsonl("logs/commands.jsonl")
    assert rows
    for r in rows:
        assert r["ts"] and NAME.match(r["sandbox_name"]) and r["command"].strip()
        assert r["decision"] in {"allow", "block"}
        assert r["execution_target"] == "celesto_sandbox"


def test_capabilities():
    caps = load("reports/capabilities.json")["capabilities"]
    ids = [c["id"] for c in caps]
    assert len(caps) >= 2 and len(set(ids)) == len(ids) and set(ids) <= CAPS
    for c in caps:
        assert len(c["why"]) >= 80
        assert (ROOT / c["evidence_path"]).exists()


def test_lifecycle():
    lc = load("reports/lifecycle.json")
    assert lc["cleanup_on_success"] is True and lc["cleanup_on_failure"] is True and lc["cleanup_on_interrupt"] is True
    names = lc["sandbox_names"]
    assert names and len(set(names)) == len(names) and all(NAME.match(n) for n in names)
    seen = {r["sandbox_name"] for r in jsonl("logs/commands.jsonl")}
    seen |= {r["sandbox_name"] for r in load("reports/reliability.json")["runs"]}
    assert set(names) <= seen


def _median(xs):
    xs = sorted(xs)
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def test_reliability():
    r = load("reports/reliability.json")
    runs = r["runs"]
    n = len(runs)
    assert n >= 20 and r["run_count"] == n
    names = [x["sandbox_name"] for x in runs]
    assert len(set(names)) == n and all(NAME.match(x) for x in names)
    assert all(x["fresh"] is True and x["wall_clock_s"] >= 0 and x["boot_to_ready_s"] >= 0 and x["cost_usd"] >= 0 for x in runs)
    walls = sorted(x["wall_clock_s"] for x in runs)
    assert abs(r["success_rate"] - sum(1 for x in runs if x["success"]) / n) <= 0.001
    assert abs(r["median_wall_clock_s"] - _median(walls)) <= 0.001
    assert abs(r["p90_wall_clock_s"] - walls[math.ceil(0.9 * n) - 1]) <= 0.001
    assert abs(r["median_boot_to_ready_s"] - _median([x["boot_to_ready_s"] for x in runs])) <= 0.001
    assert abs(r["total_cost_usd"] - sum(x["cost_usd"] for x in runs)) <= 0.01
    assert r["postmortem_path"] == "reports/postmortem.md"
    assert len((ROOT / "reports/postmortem.md").read_text()) >= 200


def test_containment():
    c = load("reports/containment.json")
    assert c["attack"] in {"prompt_injection_exfil", "destructive_command", "suspicious_package"}
    assert c["blocked"] is True and c["host_untouched"] is True
    assert c["evidence_paths"] and all((ROOT / p).exists() for p in c["evidence_paths"])


def test_failure_policy():
    f = load("reports/failure_policy.json")
    assert f["failed_step"] == 7 and f["total_steps"] == 10
    assert f["policy"] in {"resume", "rollback", "fresh"} and len(f["rationale"]) >= 200
    assert f["trace_path"] == "reports/failure_trace.jsonl"
    assert any(e.get("event") == "policy_applied" and e.get("policy") == f["policy"] for e in jsonl(f["trace_path"]))


def test_concurrency():
    c = load("reports/concurrency.json")
    jobs = c["jobs"]
    names = [j["sandbox_name"] for j in jobs]
    assert len(jobs) >= 5 and len(set(names)) == len(names) and all(NAME.match(n) for n in names)
    assert all(j["started_at"] for j in jobs) and len(c["breakage_notes"]) >= 40


def test_readme_phrases():
    t = (ROOT / "README.md").read_text()
    for p in ("Problem statement", "How I used Celesto", "Eval report", "Containment test", "State and failure design", "Setup"):
        assert p in t, p
