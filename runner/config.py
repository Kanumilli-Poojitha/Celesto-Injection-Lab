import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RATE_PER_HOUR = float(os.environ.get("SANDBOX_RATE_USD_PER_HOUR", "0.015"))  # Micro size, per brief


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Tiny .env loader so PowerShell users don't have to export variables by hand."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


@dataclass
class Paths:
    reports: Path
    logs: Path

    @property
    def commands_log(self) -> Path:
        return self.logs / "commands.jsonl"

    @property
    def evidence(self) -> Path:
        return self.reports / "evidence"

    def ensure(self) -> "Paths":
        for p in (self.reports, self.logs, self.evidence, self.evidence / "runs"):
            p.mkdir(parents=True, exist_ok=True)
        return self


def paths_for(real: bool) -> Paths:
    """Real Celesto runs write the graded files; mock runs go to *_dryrun so they can't pollute them."""
    if real:
        return Paths(ROOT / "reports", ROOT / "logs").ensure()
    return Paths(ROOT / "reports_dryrun", ROOT / "logs_dryrun").ensure()
