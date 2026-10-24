import pytest
import os

from runner.backend import BackendError, CelestoCLIBackend, redact_sensitive_text


class FakeComputers:
    def __init__(self):
        self.calls = []
        self.deleted = False

    def _request(self, method, path, *, json_body, headers):
        self.calls.append(("create", method, path, json_body, headers["Idempotency-Key"]))
        return {"id": "cloud-123", "name": "generated-by-celesto", "api_key": "cel_pat_secret"}

    def exec(self, computer_id, command, *, timeout):
        self.calls.append(("exec", computer_id, command, timeout))
        return {"exit_code": 7, "stdout": "partial", "stderr": "failed"}

    def stop(self, computer_id):
        self.calls.append(("stop", computer_id))
        return {"id": computer_id, "status": "stopped"}

    def start(self, computer_id):
        self.calls.append(("start", computer_id))
        return {"id": computer_id, "status": "running"}

    def get(self, computer_id):
        self.calls.append(("get", computer_id))
        return {"id": computer_id, "status": "running"}

    def delete(self, computer_id):
        self.calls.append(("delete", computer_id))
        self.deleted = True
        return {"id": computer_id, "status": "deleted"}


class FakeClient:
    def __init__(self):
        self.computers = FakeComputers()


def test_sdk_backend_maps_local_name_and_uses_cloud_id():
    computers = FakeComputers()
    backend = CelestoCLIBackend(client=FakeClient())
    backend.computers = computers

    backend.create("sbx-local123")
    result = backend.exec("sbx-local123", "printf hello", timeout=12)
    backend.stop("sbx-local123")
    backend.start("sbx-local123")
    assert backend.exists("sbx-local123")
    assert backend.delete("sbx-local123")

    assert result.exit_code == 7
    assert result.stdout == "partial"
    assert computers.calls == [
        ("create", "POST", "/computers", {}, computers.calls[0][4]),
        ("exec", "cloud-123", "printf hello", 12),
        ("stop", "cloud-123"),
        ("start", "cloud-123"),
        ("get", "cloud-123"),
        ("delete", "cloud-123"),
    ]
    assert "cel_pat_secret" not in backend.last_raw
    assert "cloud-123" in backend.last_raw


def test_sdk_backend_reports_command_api_failures_without_claiming_success():
    class FailingComputers(FakeComputers):
        def exec(self, computer_id, command, *, timeout):
            raise RuntimeError("remote command unavailable")

    client = FakeClient()
    client.computers = FailingComputers()
    backend = CelestoCLIBackend(client=client)
    backend.create("sbx-failure01")

    result = backend.exec("sbx-failure01", "false")

    assert result.exit_code == 124
    assert "remote command unavailable" in result.stderr


def test_sdk_backend_surfaces_creation_failure():
    class FailingComputers(FakeComputers):
        def _request(self, method, path, *, json_body, headers):
            raise RuntimeError("quota exceeded")

    client = FakeClient()
    client.computers = FailingComputers()
    backend = CelestoCLIBackend(client=client)

    with pytest.raises(BackendError, match="create failed: quota exceeded"):
        backend.create("sbx-createfail")
    assert backend.delete("sbx-createfail") is False


def test_creation_retry_reuses_idempotency_key():
    class RetryingComputers(FakeComputers):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def _request(self, method, path, *, json_body, headers):
            self.attempts += 1
            self.calls.append(("create", method, path, json_body, headers["Idempotency-Key"]))
            if self.attempts == 1:
                raise RuntimeError("temporary failure")
            return {"id": "cloud-retried"}

    computers = RetryingComputers()
    client = FakeClient()
    client.computers = computers
    backend = CelestoCLIBackend(client=client)

    with pytest.raises(BackendError, match="temporary failure"):
        backend.create("sbx-retry01")
    backend.create("sbx-retry01")

    assert computers.calls[0][4] == computers.calls[1][4]
    assert backend._ids["sbx-retry01"] == "cloud-retried"


def test_sdk_backend_requires_creation_mapping():
    backend = CelestoCLIBackend(client=FakeClient())

    with pytest.raises(BackendError, match="no Celesto computer is mapped"):
        backend.start("sbx-missing1")


def test_sensitive_values_are_redacted_from_diagnostics(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "gsk_test_secret_value")
    assert redact_sensitive_text("Authorization gsk_test_secret_value") == "Authorization <redacted>"


def test_sdk_errors_redact_credentials(monkeypatch):
    monkeypatch.setenv("CELESTO_API_KEY", "cel_pat_test_secret")

    class FailingComputers(FakeComputers):
        def exec(self, computer_id, command, *, timeout):
            raise RuntimeError("request failed for cel_pat_test_secret")

    client = FakeClient()
    client.computers = FailingComputers()
    backend = CelestoCLIBackend(client=client)
    backend.create("sbx-errorredact")

    result = backend.exec("sbx-errorredact", "true")

    assert "cel_pat_test_secret" not in result.stderr
    assert "<redacted>" in result.stderr
