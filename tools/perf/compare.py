#!/usr/bin/env python3
"""Compare two Locust _stats.csv reports and print a diff table.

Usage:
    uv run python compare.py reports/run1_stats.csv reports/run2_stats.csv
    uv run python compare.py reports/run1_stats.csv reports/run2_stats.csv --detail
    uv run python compare.py reports/run1_stats.csv reports/run2_stats.csv --format csv
    uv run python compare.py reports/run1_stats.csv reports/run2_stats.csv --threshold 10

The first file is treated as the baseline, the second as the new run.
Default output shows aggregate-only summary. Use --detail for per-endpoint breakdown.
Regressions (higher latency, more failures) are flagged.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EndpointStats:
    method: str
    name: str
    count: int
    failures: int
    avg_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    rps: float
    fail_rate: float


def load_stats(path: Path) -> dict[str, EndpointStats]:
    """Load per-endpoint stats from a Locust _stats.csv."""
    results: dict[str, EndpointStats] = {}
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            method = row["Type"].strip()
            name = row["Name"].strip()
            if name == "Aggregated":
                continue
            if not method:
                continue
            count = int(row["Request Count"])
            failures = int(row["Failure Count"])
            key = f"{method} {name}"
            results[key] = EndpointStats(
                method=method,
                name=name,
                count=count,
                failures=failures,
                avg_ms=float(row["Average Response Time"]),
                median_ms=float(row["Median Response Time"]),
                p95_ms=float(row["95%"]),
                p99_ms=float(row["99%"]),
                min_ms=float(row["Min Response Time"]),
                max_ms=float(row["Max Response Time"]),
                rps=float(row["Requests/s"]),
                fail_rate=(failures / count * 100) if count > 0 else 0.0,
            )
    return results


def load_aggregate(path: Path) -> EndpointStats | None:
    """Load the Aggregated row from a Locust _stats.csv."""
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["Name"].strip() != "Aggregated":
                continue
            count = int(row["Request Count"])
            failures = int(row["Failure Count"])
            return EndpointStats(
                method="",
                name="Aggregated",
                count=count,
                failures=failures,
                avg_ms=float(row["Average Response Time"]),
                median_ms=float(row["Median Response Time"]),
                p95_ms=float(row["95%"]),
                p99_ms=float(row["99%"]),
                min_ms=float(row["Min Response Time"]),
                max_ms=float(row["Max Response Time"]),
                rps=float(row["Requests/s"]),
                fail_rate=(failures / count * 100) if count > 0 else 0.0,
            )
    return None


def load_run_duration(stats_path: Path) -> tuple[float, int] | None:
    """Derive run duration and peak user count from the _stats_history.csv.

    Returns (duration_seconds, max_users) or None if the history file
    is missing or empty.
    """
    history_path = Path(
        str(stats_path).replace("_stats.csv", "_stats_history.csv"),
    )
    if not history_path.exists():
        return None

    first_ts: int | None = None
    last_ts: int | None = None
    max_users = 0

    with history_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = int(row["Timestamp"])
            users = int(row["User Count"])
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            max_users = max(max_users, users)

    if first_ts is None or last_ts is None:
        return None

    return (float(last_ts - first_ts), max_users)


def fmt_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration string."""
    m, s = divmod(int(seconds), 60)
    if m == 0:
        return f"{s}s"
    return f"{m}m{s}s"


def pct_delta(old: float, new: float) -> str:
    """Format a percentage delta."""
    if old == 0:
        return "n/a"
    pct = ((new - old) / old) * 100
    sign = "+" if pct > 0 else ""
    return f"{sign}{pct:.1f}%"


def flag(old: float, new: float, threshold_pct: float) -> str:
    """Return a regression/improvement flag."""
    if old == 0:
        return ""
    pct = ((new - old) / old) * 100
    if pct > threshold_pct:
        return "REGRESSION"
    if pct < -threshold_pct:
        return "IMPROVED"
    return ""


def print_summary(
    baseline_agg: EndpointStats,
    current_agg: EndpointStats,
    baseline_eps: dict[str, EndpointStats],
    current_eps: dict[str, EndpointStats],
    threshold: float,
    baseline_label: str,
    current_label: str,
    baseline_run: tuple[float, int] | None,
    current_run: tuple[float, int] | None,
) -> None:
    """Print aggregate comparison summary."""
    b = baseline_agg
    c = current_agg

    all_keys = set(baseline_eps) | set(current_eps)
    common = set(baseline_eps) & set(current_eps)
    regressions = sum(
        1 for k in common
        if flag(baseline_eps[k].p95_ms, current_eps[k].p95_ms, threshold)
        == "REGRESSION"
    )
    improvements = sum(
        1 for k in common
        if flag(baseline_eps[k].p95_ms, current_eps[k].p95_ms, threshold)
        == "IMPROVED"
    )
    new_eps = len(set(current_eps) - set(baseline_eps))
    removed_eps = len(set(baseline_eps) - set(current_eps))

    print(f"## Comparison: {baseline_label} vs {current_label}\n")

    print("| Metric | Baseline | Current | Delta |")
    print("|--------|----------|---------|-------|")

    if baseline_run and current_run:
        b_dur, b_users = baseline_run
        c_dur, c_users = current_run
        print(
            f"| Duration | {fmt_duration(b_dur)} | {fmt_duration(c_dur)} "
            f"| {pct_delta(b_dur, c_dur)} |"
        )
        print(
            f"| Peak users | {b_users} | {c_users} "
            f"| {pct_delta(b_users, c_users)} |"
        )

    print(
        f"| Total requests | {b.count:,} | {c.count:,} "
        f"| {pct_delta(b.count, c.count)} |"
    )
    print(
        f"| Failed requests | {b.failures:,} | {c.failures:,} "
        f"| {pct_delta(b.failures, c.failures)} |"
    )
    print(
        f"| Failure rate | {b.fail_rate:.2f}% | {c.fail_rate:.2f}% "
        f"| {pct_delta(b.fail_rate, c.fail_rate)} |"
    )
    print(
        f"| Requests/s | {b.rps:.1f} | {c.rps:.1f} "
        f"| {pct_delta(b.rps, c.rps)} |"
    )
    print(
        f"| Avg response (ms) | {b.avg_ms:.1f} | {c.avg_ms:.1f} "
        f"| {pct_delta(b.avg_ms, c.avg_ms)} |"
    )
    print(
        f"| Median response (ms) | {b.median_ms:.0f} | {c.median_ms:.0f} "
        f"| {pct_delta(b.median_ms, c.median_ms)} |"
    )
    print(
        f"| p95 response (ms) | {b.p95_ms:.0f} | {c.p95_ms:.0f} "
        f"| {pct_delta(b.p95_ms, c.p95_ms)} |"
    )
    print(
        f"| p99 response (ms) | {b.p99_ms:.0f} | {c.p99_ms:.0f} "
        f"| {pct_delta(b.p99_ms, c.p99_ms)} |"
    )
    print(
        f"| Max response (ms) | {b.max_ms:.0f} | {c.max_ms:.0f} "
        f"| {pct_delta(b.max_ms, c.max_ms)} |"
    )
    print(
        f"| Unique endpoints | {len(baseline_eps)} | {len(current_eps)} "
        f"| {new_eps} new, {removed_eps} removed |"
    )

    print(f"\n**{regressions} regressions, {improvements} improvements** "
          f"across {len(common)} common endpoints "
          f"(p95 threshold: {threshold:.0f}%)")

    if regressions > 0:
        print("\nTop regressions (by p95 delta):\n")
        print("| Endpoint | p95 old | p95 new | Delta |")
        print("|----------|---------|---------|-------|")
        regressed = [
            (k, baseline_eps[k], current_eps[k])
            for k in common
            if flag(
                baseline_eps[k].p95_ms, current_eps[k].p95_ms, threshold
            ) == "REGRESSION"
        ]
        regressed.sort(
            key=lambda x: x[2].p95_ms - x[1].p95_ms, reverse=True,
        )
        for key, bp, cp in regressed[:10]:
            print(
                f"| {key} | {bp.p95_ms:.0f} | {cp.p95_ms:.0f} "
                f"| {pct_delta(bp.p95_ms, cp.p95_ms)} |"
            )

    if improvements > 0:
        print("\nTop improvements (by p95 delta):\n")
        print("| Endpoint | p95 old | p95 new | Delta |")
        print("|----------|---------|---------|-------|")
        improved = [
            (k, baseline_eps[k], current_eps[k])
            for k in common
            if flag(
                baseline_eps[k].p95_ms, current_eps[k].p95_ms, threshold
            ) == "IMPROVED"
        ]
        improved.sort(key=lambda x: x[1].p95_ms - x[2].p95_ms, reverse=True)
        for key, bp, cp in improved[:10]:
            print(
                f"| {key} | {bp.p95_ms:.0f} | {cp.p95_ms:.0f} "
                f"| {pct_delta(bp.p95_ms, cp.p95_ms)} |"
            )


def print_detail_markdown(
    baseline: dict[str, EndpointStats],
    current: dict[str, EndpointStats],
    threshold: float,
    baseline_label: str,
    current_label: str,
) -> None:
    """Print a per-endpoint markdown comparison table."""
    all_keys = sorted(set(baseline) | set(current))
    if not all_keys:
        print("No endpoints to compare.")
        return

    print(f"## Detail: {baseline_label} vs {current_label}\n")
    print(f"Threshold: {threshold:.0f}% (deltas beyond this are flagged)\n")
    print(
        "| Endpoint | Reqs (old/new) | Avg ms (old/new) "
        "| p95 ms (old/new) | p99 ms (old/new) | Fail% (old/new) | Flag |"
    )
    print(
        "|----------|---------------|---------------"
        "|-----------------|-----------------|----------------|------|"
    )

    regressions = 0
    improvements = 0

    for key in all_keys:
        b = baseline.get(key)
        c = current.get(key)

        if b and not c:
            print(f"| {key} | {b.count}/- | REMOVED | | | | |")
            continue
        if c and not b:
            print(
                f"| {key} | -/{c.count} | NEW {c.avg_ms:.0f}ms "
                f"| {c.p95_ms:.0f}ms | {c.p99_ms:.0f}ms "
                f"| {c.fail_rate:.1f}% | NEW |"
            )
            continue

        assert b is not None and c is not None
        f = flag(b.p95_ms, c.p95_ms, threshold)
        if f == "REGRESSION":
            regressions += 1
        elif f == "IMPROVED":
            improvements += 1

        print(
            f"| {key} "
            f"| {b.count}/{c.count} "
            f"| {b.avg_ms:.0f}/{c.avg_ms:.0f} "
            f"| {b.p95_ms:.0f}/{c.p95_ms:.0f} "
            f"| {b.p99_ms:.0f}/{c.p99_ms:.0f} "
            f"| {b.fail_rate:.1f}/{c.fail_rate:.1f} "
            f"| {f} |"
        )

    print(f"\n**{regressions} regressions, {improvements} improvements** "
          f"(threshold: {threshold:.0f}%)")


def print_csv_output(
    baseline: dict[str, EndpointStats],
    current: dict[str, EndpointStats],
    threshold: float,
) -> None:
    """Print a CSV comparison."""
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "Endpoint",
        "Reqs (old)", "Reqs (new)",
        "Avg ms (old)", "Avg ms (new)", "Avg delta%",
        "p95 ms (old)", "p95 ms (new)", "p95 delta%",
        "p99 ms (old)", "p99 ms (new)", "p99 delta%",
        "Fail% (old)", "Fail% (new)",
        "Flag",
    ])

    for key in sorted(set(baseline) | set(current)):
        b = baseline.get(key)
        c = current.get(key)

        if b and not c:
            writer.writerow([key, b.count, 0,
                             f"{b.avg_ms:.1f}", "", "",
                             f"{b.p95_ms:.0f}", "", "",
                             f"{b.p99_ms:.0f}", "", "",
                             f"{b.fail_rate:.1f}", "",
                             "REMOVED"])
            continue
        if c and not b:
            writer.writerow([key, 0, c.count,
                             "", f"{c.avg_ms:.1f}", "",
                             "", f"{c.p95_ms:.0f}", "",
                             "", f"{c.p99_ms:.0f}", "",
                             "", f"{c.fail_rate:.1f}",
                             "NEW"])
            continue

        assert b is not None and c is not None

        def pct(old: float, new: float) -> str:
            if old == 0:
                return ""
            return f"{((new - old) / old) * 100:.1f}"

        writer.writerow([
            key,
            b.count, c.count,
            f"{b.avg_ms:.1f}", f"{c.avg_ms:.1f}", pct(b.avg_ms, c.avg_ms),
            f"{b.p95_ms:.0f}", f"{c.p95_ms:.0f}", pct(b.p95_ms, c.p95_ms),
            f"{b.p99_ms:.0f}", f"{c.p99_ms:.0f}", pct(b.p99_ms, c.p99_ms),
            f"{b.fail_rate:.1f}", f"{c.fail_rate:.1f}",
            flag(b.p95_ms, c.p95_ms, threshold),
        ])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare two Locust _stats.csv reports",
    )
    parser.add_argument("baseline", type=Path, help="Baseline _stats.csv")
    parser.add_argument("current", type=Path, help="New run _stats.csv")
    parser.add_argument(
        "--threshold", type=float, default=20.0,
        help="Percentage delta to flag as regression/improvement (default: 20)",
    )
    parser.add_argument(
        "--format", choices=["markdown", "csv"], default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--detail", action="store_true",
        help="Show per-endpoint breakdown instead of aggregate summary",
    )
    args = parser.parse_args()

    if not args.baseline.exists():
        sys.exit(f"Baseline file not found: {args.baseline}")
    if not args.current.exists():
        sys.exit(f"Current file not found: {args.current}")

    baseline_label = args.baseline.stem.replace("_stats", "")
    current_label = args.current.stem.replace("_stats", "")

    if args.format == "csv":
        baseline = load_stats(args.baseline)
        current = load_stats(args.current)
        print_csv_output(baseline, current, args.threshold)
    elif args.detail:
        baseline = load_stats(args.baseline)
        current = load_stats(args.current)
        print_detail_markdown(baseline, current, args.threshold,
                              baseline_label, current_label)
    else:
        baseline_agg = load_aggregate(args.baseline)
        current_agg = load_aggregate(args.current)
        if not baseline_agg or not current_agg:
            sys.exit("Could not find Aggregated row in one of the files. "
                     "Use --detail for per-endpoint comparison.")
        baseline_eps = load_stats(args.baseline)
        current_eps = load_stats(args.current)
        baseline_run = load_run_duration(args.baseline)
        current_run = load_run_duration(args.current)
        print_summary(baseline_agg, current_agg,
                      baseline_eps, current_eps,
                      args.threshold, baseline_label, current_label,
                      baseline_run, current_run)


if __name__ == "__main__":
    main()
