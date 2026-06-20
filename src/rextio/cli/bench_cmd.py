from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from rextio.bench.runner import BenchError, BenchResult, run_benchmark


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    try:
        result = run_benchmark(project_root, args.target)
    except BenchError as exc:
        print(f"Rextio bench {args.target}")
        print(f"RXT060 Benchmark failed: {exc}")
        return 1

    report_path = write_bench_report(project_root, result)
    print(f"Rextio bench {args.target}")
    print(f"iterations:       {result.iterations}")
    print(f"Python fallback:  {result.fallback_ms:.3f} ms")
    print(f"Rust native:      {result.native_ms:.3f} ms")
    print(f"Speedup:          {result.speedup:.2f}x")
    print(f"wrote:            {report_path}")
    return 0


def write_bench_report(project_root: Path, result: BenchResult) -> Path:
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "bench.json"
    report_path.write_text(
        json.dumps({"status": "benchmarked", **result.to_dict()}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return report_path
