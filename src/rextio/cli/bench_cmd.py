"""The ``rextio bench`` command."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from rextio.bench.runner import BenchError, BenchResult, run_benchmark
from rextio.cli.reporter import Reporter


def run(args: Namespace) -> int:
    """Run the bench command; return the process exit code."""
    reporter = Reporter.from_args(args)
    project_root = Path(args.project_root).resolve()
    try:
        result = run_benchmark(project_root, args.target, embed_helpers=args.embed_helpers)
    except BenchError as exc:
        reporter.error(f"RXT060 Benchmark failed for {args.target}: {exc}")
        return 1

    report_path = write_bench_report(project_root, result)
    text = "\n".join(
        [
            f"Rextio bench {args.target}",
            f"iterations:       {result.iterations}",
            f"Python fallback:  {result.fallback_ms:.3f} ms",
            f"Rust native:      {result.native_ms:.3f} ms",
            f"Speedup:          {result.speedup:.2f}x",
            f"wrote:            {report_path}",
        ]
    )
    reporter.print_result(text=text, data={"status": "benchmarked", **result.to_dict()})
    return 0


def write_bench_report(project_root: Path, result: BenchResult) -> Path:
    """Write the bench JSON report and return its path."""
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "bench.json"
    report_path.write_text(
        json.dumps({"status": "benchmarked", **result.to_dict()}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return report_path
