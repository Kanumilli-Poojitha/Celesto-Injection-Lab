"""Sandbox backends. Every guest action goes through one of these; nothing runs on the host.

CelestoBackend uses the installed Celesto SDK. The SDK does not accept a
caller-supplied computer name, so local names are mapped to returned cloud IDs.
"""
import json
import os
import random
import re
import string
import time
import uuid
from dataclasses import dataclass


class BackendError(RuntimeError):
    pass


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


def new_sandbox_name() -> str:
    return "sbx-" + "".join(random.SystemRandom().choices(string.ascii_lowercase + string.digits, k=10))


_SENSITIVE_KEY = re.compile(r"(api[_-]?key|authorization|password|secret|token)", re.I)
_SENSITIVE_VALUE = re.compile(r"(?i)(?:cel_pat_[A-Za-z0-9_-]+|bearer\s+[A-Za-z0-9._-]+)")


def redact_sensitive_text(value: str) -> str:
    secrets = {
        candidate
        for key, candidate in os.environ.items()
        if candidate and any(word in key.lower() for word in ("key", "token", "secret", "password"))
    }
    redacted = _SENSITIVE_VALUE.sub("<redacted>", value)
    for secret in sorted(secrets, key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    return redacted


def _redact(value):
    if isinstance(value, dict):
        return {
            str(k): "<redacted>" if _SENSITIVE_KEY.search(str(k)) else _redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


class CelestoCLIBackend:
    real = True

    def __init__(self, client=None, timeout: int = 240):
        self.timeout = timeout
        self.last_raw = ""
        self._ids: dict[str, str] = {}
        self._creation_keys: dict[str, str] = {}
        try:
            if client is None:
                from celesto.sdk.client import _CelestoClient
                client = _CelestoClient(api_key=os.environ.get("CELESTO_API_KEY"))
            self.client = client
            self.computers = client.computers
        except (ImportError, AttributeError, TypeError) as exc:
            raise BackendError("Celesto SDK 0.0.14 is not available or could not be initialized") from exc

    def _record(self, operation, payload):
        self.last_raw = json.dumps(
            {"operation": operation, "response": _redact(payload)},
            sort_keys=True,
            default=str,
        )

    def _cloud_id(self, name):
        try:
            return self._ids[name]
        except KeyError as exc:
            raise BackendError(f"no Celesto computer is mapped for local name {name}") from exc

    @staticmethod
    def _response_id(payload):
        if not isinstance(payload, dict):
            raise BackendError("Celesto returned an invalid computer response")
        identifier = payload.get("id") or payload.get("name")
        if not isinstance(identifier, str) or not identifier:
            raise BackendError("Celesto response did not include a computer id or name")
        return identifier

    def create(self, name: str) -> None:
        if name in self._ids:
            raise BackendError(f"local sandbox {name} is already mapped")
        idempotency_key = self._creation_keys.setdefault(name, str(uuid.uuid4()))
        try:
            payload = self.computers._request(
                "POST",
                "/computers",
                json_body={},
                headers={"Idempotency-Key": idempotency_key},
            )
        except Exception as exc:
            raise BackendError(f"create failed: {redact_sensitive_text(str(exc))[:300]}") from exc
        self._record("create", payload)
        try:
            self._ids[name] = self._response_id(payload)
        except BackendError:
            raise
        else:
            self._creation_keys.pop(name, None)

    def exec(self, name: str, command: str, timeout: int = 120) -> ExecResult:
        try:
            payload = self.computers.exec(self._cloud_id(name), command, timeout=min(timeout, 300))
        except Exception as exc:
            return ExecResult(124, "", f"Celesto command failed: {redact_sensitive_text(str(exc))[:300]}")
        self._record("exec", payload)
        if not isinstance(payload, dict):
            return ExecResult(1, "", "Celesto returned an invalid command response")
        return ExecResult(
            int(payload.get("exit_code", 1)),
            str(payload.get("stdout", "")),
            str(payload.get("stderr", "")),
        )

    def wait_ready(self, name: str, timeout: int = 180) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.exec(name, "true", timeout=30).exit_code == 0:
                return
            time.sleep(1.5)
        raise BackendError(f"{name} not ready after {timeout}s")

    def stop(self, name: str) -> None:
        try:
            payload = self.computers.stop(self._cloud_id(name))
        except Exception as exc:
            raise BackendError(f"stop failed: {redact_sensitive_text(str(exc))[:300]}") from exc
        self._record("stop", payload)

    def start(self, name: str) -> None:
        try:
            payload = self.computers.start(self._cloud_id(name))
        except Exception as exc:
            raise BackendError(f"start failed: {redact_sensitive_text(str(exc))[:300]}") from exc
        self._record("start", payload)

    def delete(self, name: str) -> bool:
        if name not in self._ids:
            return False
        cloud_id = self._cloud_id(name)
        try:
            payload = self.computers.delete(cloud_id)
        except Exception as exc:
            safe_error = redact_sensitive_text(str(exc))
            msg = safe_error.lower()
            if "not found" in msg or "does not exist" in msg:
                self._ids.pop(name, None)
                return False
            raise BackendError(f"delete failed: {safe_error[:300]}") from exc
        self._record("delete", payload)
        self._ids.pop(name, None)
        self._creation_keys.pop(name, None)
        return True

    def exists(self, name: str) -> bool:
        if name not in self._ids:
            return False
        try:
            payload = self.computers.get(self._ids[name])
        except Exception as exc:
            safe_error = redact_sensitive_text(str(exc))
            if "not found" in safe_error.lower() or "does not exist" in safe_error.lower():
                self._ids.pop(name, None)
                return False
            raise BackendError(f"get failed: {safe_error[:300]}") from exc
        self._record("get", payload)
        return isinstance(payload, dict)


class MockBackend:
    """In-memory fake guest for offline tests. NEVER used for graded reports."""
    real = False

    def __init__(self, lose_state_on_stop: bool = False):
        self.boxes: dict[str, dict] = {}
        self.lose_state_on_stop = lose_state_on_stop
        self.created: list[str] = []
        self.deleted: list[str] = []

    def create(self, name):
        if name in self.boxes:
            raise BackendError("name collision")
        self.boxes[name] = {"files": {}, "running": True}
        self.created.append(name)

    def wait_ready(self, name):
        self._box(name)

    def _box(self, name):
        if name not in self.boxes:
            raise BackendError(f"{name} does not exist")
        return self.boxes[name]

    def stop(self, name):
        b = self._box(name)
        b["running"] = False
        if self.lose_state_on_stop:
            b["files"] = {}

    def start(self, name):
        self._box(name)["running"] = True

    def delete(self, name):
        if name not in self.boxes:
            return False
        del self.boxes[name]
        self.deleted.append(name)
        return True

    def exists(self, name):
        return name in self.boxes

    @staticmethod
    def _norm(p):
        return p.strip("\"'").replace("$HOME", "/home/agent").replace("~", "/home/agent")

    def exec(self, name, command, timeout=120):
        import base64
        b = self._box(name)
        if not b["running"]:
            raise BackendError("sandbox is stopped")
        f = b["files"]
        c = command.replace("$HOME", "/home/agent").replace("~", "/home/agent")
        if re.search(r"(^|[\s;|&(/])(curl|wget)\b", c):
            return ExecResult(6, "", "curl: (6) Could not resolve host: exfil.invalid")
        if re.search(r"\brm\s+-\w+\s+[\"']?/home/agent", c):
            for k in [k for k in f if k.startswith("/home/agent")]:
                del f[k]
            return ExecResult(0, "", "")
        m = re.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d >{1,2} (\S+)", c)
        if m:
            f[self._norm(m.group(2))] = base64.b64decode(m.group(1)).decode()
            return ExecResult(0, "", "")
        m = re.search(r"printf 'API_KEY=%s\\n' '([^']+)' > (\S+)", c)
        if m:
            f[self._norm(m.group(2))] = f"API_KEY={m.group(1)}\n"
            return ExecResult(0, "", "")
        if "test -d /home/agent/work" in c.replace(chr(34), ""):
            has = any(k.startswith("/home/agent/work/") for k in f)
            return ExecResult(0, "yes" if has else "no", "")
        tests = re.findall(r"test -s (\S+)", c)
        if tests:
            ok = all(f.get(self._norm(t)) for t in tests)
            return ExecResult(0 if ok else 1, "", "")
        m = re.search(r"grep -c \. (\S+)", c)
        if m:
            txt = f.get(self._norm(m.group(1)), "")
            return ExecResult(0, str(sum(1 for ln in txt.splitlines() if ln.strip())), "")
        m = re.match(r"\s*cat (.+)$", c)
        if m:
            parts = [self._norm(x) for x in m.group(1).split()]
            if any(p not in f for p in parts):
                return ExecResult(1, "", "cat: no such file")
            return ExecResult(0, "".join(f[p] for p in parts), "")
        return ExecResult(0, "ok", "")
