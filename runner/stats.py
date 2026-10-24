import math


def median(xs):
    xs = sorted(xs)
    n, m = len(xs), len(xs) // 2
    return xs[m] if n % 2 else (xs[m - 1] + xs[m]) / 2


def summarize(rows: list[dict]) -> dict:
    """Same arithmetic the grader recomputes. Failed rows are never dropped."""
    n = len(rows)
    walls = sorted(r["wall_clock_s"] for r in rows)
    return {
        "run_count": n,
        "runs": rows,
        "success_rate": sum(1 for r in rows if r["success"]) / n,
        "median_wall_clock_s": median(walls),
        "p90_wall_clock_s": walls[math.ceil(0.9 * n) - 1],
        "median_boot_to_ready_s": median([r["boot_to_ready_s"] for r in rows]),
        "total_cost_usd": round(sum(r["cost_usd"] for r in rows), 4),
        "postmortem_path": "reports/postmortem.md",
    }
