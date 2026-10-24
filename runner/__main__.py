"""python -m runner <smoke|eval|containment|failure|concurrency|lifecycle|stats> [--backend celesto|mock]"""
import argparse
import json
import os
import sys

from . import jobs
from .agent import LLMClient, MockLLM
from .backend import CelestoCLIBackend, MockBackend, new_sandbox_name
from .config import load_dotenv, paths_for
from .ledger import Ledger
from .lifecycle import managed_sandbox
from .stats import summarize


def main(argv=None):
    ap = argparse.ArgumentParser(prog="runner")
    ap.add_argument("cmd", choices=["smoke", "eval", "containment", "failure", "concurrency", "lifecycle", "stats"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--backend", choices=["celesto", "mock"], default="celesto")
    ap.add_argument("--llm", choices=["real", "mock"], default=None)
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--n", type=int, default=3, help="LLM runs per condition in containment")
    ap.add_argument("--jobs", type=int, default=5)
    ap.add_argument("--policy", choices=["resume", "fresh"], default="resume")
    ap.add_argument("--clean", action="store_true", help="use clean (non-poisoned) fixtures")
    ap.add_argument("--no-defense", action="store_true", help="hook logs but never blocks")
    a = ap.parse_args(argv)
    load_dotenv()
    real = a.backend == "celesto"
    paths = paths_for(real)
    if not real:
        print("MOCK backend: outputs go to reports_dryrun/ and logs_dryrun/, not the graded files.")
    backend = CelestoCLIBackend() if real else MockBackend()
    llm_mode = a.llm or ("real" if real else "mock")
    llm = LLMClient.from_env() if llm_mode == "real" and a.cmd in ("eval", "containment", "failure") else MockLLM()
    ledger = Ledger(os.environ.get("LEDGER_URL", "http://localhost:8080") if real else None)

    if a.cmd == "smoke":
        name = new_sandbox_name()
        with managed_sandbox(backend, name):
            backend.create(name)
            print("create ->", getattr(backend, "last_raw", "ok"))
            backend.wait_ready(name)
            r = backend.exec(name, "echo hello && uname -a")
            print("exec ->", getattr(backend, "last_raw", ""), "\nparsed:", r)
        print("deleted:", not backend.exists(name))
    elif a.cmd == "eval":
        jobs.run_eval(backend, llm, paths, ledger, a.runs, poisoned=not a.clean, defense=not a.no_defense)
    elif a.cmd == "containment":
        jobs.run_containment(backend, llm, paths, ledger, a.n)
    elif a.cmd == "failure":
        jobs.run_failure_demo(backend, llm, paths, ledger, a.policy)
    elif a.cmd == "concurrency":
        jobs.run_concurrency(backend, paths, ledger, a.jobs)
    elif a.cmd == "lifecycle":
        print(jobs.run_lifecycle_check(backend, paths))
    elif a.cmd == "stats":
        rows = json.load(open(a.arg))["rows"] if a.arg else []
        paths.reports.joinpath("reliability.json").write_text(json.dumps(summarize(rows), indent=2))


if __name__ == "__main__":
    sys.exit(main())
