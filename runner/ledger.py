import json
import sys
import urllib.request


class Ledger:
    """Best-effort client for the Postgres-backed run ledger API. Never blocks a run."""

    def __init__(self, url: str | None):
        self.url, self.warned = url, False

    def post(self, run_id, sandbox_name, state, problem_id="prompt-injection-exfil"):
        if not self.url:
            return
        body = json.dumps({"run_id": run_id, "sandbox_name": sandbox_name, "problem_id": problem_id,
                           "state": state, "execution_target": "celesto_sandbox"}).encode()
        req = urllib.request.Request(self.url.rstrip("/") + "/api/runs", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as e:
            if not self.warned:
                print(f"[ledger] unreachable ({e}); continuing without it", file=sys.stderr)
                self.warned = True
