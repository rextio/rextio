from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from rextio.bench.runner import BenchError, run_benchmark


def run(args: Namespace) -> int:
    try:
        result = run_benchmark(Path(args.project_root).resolve(), args.target)
    except BenchError as exc:
        print(f"Rextio bench {args.target}")
        print(f"RXT060 Benchmark failed: {exc}")
        return 1

    print(f"Rextio bench {args.target}")
    print(f"iterations:       {result.iterations}")
    print(f"Python fallback:  {result.fallback_ms:.3f} ms")
    print(f"Rust native:      {result.native_ms:.3f} ms")
    print(f"Speedup:          {result.speedup:.2f}x")
    return 0
