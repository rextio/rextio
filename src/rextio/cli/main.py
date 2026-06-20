from __future__ import annotations

import argparse
from collections.abc import Sequence

from rextio.cli import bench_cmd, build_cmd, check_cmd, clean_cmd, init_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rextio",
        description="Rextio Public 1 hybrid build tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create default Rextio project files.")
    init_parser.add_argument("--project-root", default=".", help="Project root to initialize.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files.")
    init_parser.set_defaults(handler=init_cmd.run)

    check_parser = subparsers.add_parser("check", help="Analyze native candidates.")
    check_parser.add_argument("project_root", nargs="?", default=".", help="Project root to check.")
    check_parser.add_argument("--json", action="store_true", help="Print structured JSON.")
    check_parser.set_defaults(handler=check_cmd.run)

    build_parser_ = subparsers.add_parser("build", help="Build a hybrid artifact.")
    build_parser_.add_argument("project_root", nargs="?", default=".", help="Project root to build.")
    build_parser_.add_argument(
        "--fallback",
        choices=("cpython", "nuitka"),
        default="cpython",
        help="Fallback backend.",
    )
    build_parser_.set_defaults(handler=build_cmd.run)

    bench_parser = subparsers.add_parser("bench", help="Benchmark a specific function.")
    bench_parser.add_argument("target", help="Fully qualified function name.")
    bench_parser.add_argument("--project-root", default=".", help="Project root to benchmark.")
    bench_parser.set_defaults(handler=bench_cmd.run)

    clean_parser = subparsers.add_parser("clean", help="Remove generated Rextio artifacts.")
    clean_parser.add_argument("project_root", nargs="?", default=".", help="Project root to clean.")
    clean_parser.set_defaults(handler=clean_cmd.run)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
