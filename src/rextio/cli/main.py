from __future__ import annotations

import argparse
from collections.abc import Sequence

from rextio.cli import bench_cmd, build_cmd, check_cmd, clean_cmd, generate_cmd, init_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rextio",
        description="Rextio 0.1.0 alpha hybrid build tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create default Rextio project files.")
    init_parser.add_argument("--project-root", default=".", help="Project root to initialize.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files.")
    init_parser.set_defaults(handler=init_cmd.run)

    check_parser = subparsers.add_parser("check", help="Analyze native candidates.")
    check_parser.add_argument("project_root", nargs="?", default=".", help="Project root to check.")
    check_parser.add_argument("--json", action="store_true", help="Print structured JSON.")
    check_parser.add_argument(
        "--native-backend",
        "--target-language",
        dest="native_backend",
        choices=("rust", "mojo", "julia"),
        default=None,
        help=(
            "Native target language. Overrides REXTIO_TARGET_LANGUAGE, "
            "REXTIO_NATIVE_BACKEND, and [build] native_backend."
        ),
    )
    _add_target_options(check_parser)
    _add_policy_options(check_parser)
    check_parser.set_defaults(handler=check_cmd.run)

    build_parser_ = subparsers.add_parser("build", help="Build a hybrid artifact.")
    build_parser_.add_argument("project_root", nargs="?", default=".", help="Project root to build.")
    build_parser_.add_argument(
        "--native-backend",
        "--target-language",
        dest="native_backend",
        choices=("rust", "mojo", "julia"),
        default=None,
        help=(
            "Native target language. Overrides REXTIO_TARGET_LANGUAGE, "
            "REXTIO_NATIVE_BACKEND, and [build] native_backend."
        ),
    )
    _add_target_options(build_parser_)
    build_parser_.add_argument(
        "--fallback",
        choices=("cpython", "nuitka"),
        default=None,
        help="Fallback backend. Overrides REXTIO_FALLBACK_BACKEND and [build] fallback_backend.",
    )
    build_parser_.add_argument(
        "--fallback-threshold",
        type=_non_negative_int,
        default=None,
        help=(
            "Python-to-native wrapper calls allowed before generated fallback is used. "
            "Overrides REXTIO_BOUNDARY_FALLBACK_THRESHOLD and [build] fallback_threshold. "
            "Use 0 to disable threshold fallback."
        ),
    )
    build_parser_.add_argument(
        "--rust-binding",
        choices=("pyo3",),
        default=None,
        help="Rust binding backend. Overrides REXTIO_RUST_BINDING and [rust] binding.",
    )
    build_parser_.add_argument(
        "--rust-build-tool",
        choices=("cargo", "maturin"),
        default=None,
        help="Rust build tool. Overrides REXTIO_RUST_BUILD_TOOL and [rust] build_tool.",
    )
    build_parser_.add_argument(
        "--nuitka-fallback",
        choices=("experimental",),
        default=None,
        help="Nuitka fallback policy. Overrides REXTIO_NUITKA_FALLBACK and [fallback] nuitka.",
    )
    build_parser_.add_argument(
        "--entrypoint",
        default=None,
        help=(
            "Generate an executable artifact for the given module:function entrypoint. "
            "Overrides REXTIO_EXECUTABLE_ENTRYPOINT and [executable] entrypoint."
        ),
    )
    build_parser_.add_argument(
        "--executable-name",
        default=None,
        help=(
            "Executable artifact name without extension. Overrides REXTIO_EXECUTABLE_NAME "
            "and [executable] name."
        ),
    )
    build_parser_.add_argument(
        "--executable-backend",
        choices=("zipapp", "nuitka"),
        default=None,
        help=(
            "Executable artifact backend to use when an entrypoint is configured. "
            "Overrides REXTIO_EXECUTABLE_BACKEND and [executable] backend."
        ),
    )
    build_parser_.add_argument(
        "--nuitka-mode",
        choices=("standalone", "onefile"),
        default=None,
        help="Nuitka executable mode. Overrides REXTIO_NUITKA_MODE and [executable] nuitka_mode.",
    )
    _add_policy_options(build_parser_)
    build_parser_.set_defaults(handler=build_cmd.run)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate Rust and Python source artifacts without compiling.",
    )
    generate_parser.add_argument(
        "project_root",
        nargs="?",
        default=".",
        help="Project root to generate source artifacts for.",
    )
    generate_parser.add_argument(
        "--native-backend",
        "--target-language",
        dest="native_backend",
        choices=("rust", "mojo", "julia"),
        default=None,
        help=(
            "Native target language. Overrides REXTIO_TARGET_LANGUAGE, "
            "REXTIO_NATIVE_BACKEND, and [build] native_backend."
        ),
    )
    _add_target_options(generate_parser)
    generate_parser.add_argument(
        "--fallback",
        choices=("cpython", "nuitka"),
        default=None,
        help="Fallback backend label. Overrides REXTIO_FALLBACK_BACKEND and [build] fallback_backend.",
    )
    generate_parser.add_argument(
        "--fallback-threshold",
        type=_non_negative_int,
        default=None,
        help=(
            "Python-to-native wrapper calls allowed before generated fallback is used. "
            "Overrides REXTIO_BOUNDARY_FALLBACK_THRESHOLD and [build] fallback_threshold. "
            "Use 0 to disable threshold fallback."
        ),
    )
    generate_parser.add_argument(
        "--rust-binding",
        choices=("pyo3",),
        default=None,
        help="Rust binding backend. Overrides REXTIO_RUST_BINDING and [rust] binding.",
    )
    generate_parser.add_argument(
        "--nuitka-fallback",
        choices=("experimental",),
        default=None,
        help="Nuitka fallback policy. Overrides REXTIO_NUITKA_FALLBACK and [fallback] nuitka.",
    )
    _add_policy_options(generate_parser)
    generate_parser.set_defaults(handler=generate_cmd.run)

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


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _key_value(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("must use KEY=VALUE")
    key, option_value = value.split("=", 1)
    if not key:
        raise argparse.ArgumentTypeError("must not use an empty key")
    return key, option_value


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target-version",
        default=None,
        help="Target language version. Overrides REXTIO_TARGET_VERSION and [target] version.",
    )
    parser.add_argument(
        "--target-build-option",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        type=_key_value,
        help=(
            "Target build/codegen option. May be passed more than once. Overrides "
            "REXTIO_TARGET_BUILD_OPTIONS and [target.build_options]."
        ),
    )
    parser.add_argument(
        "--mapper-path",
        action="append",
        default=None,
        help="Local mapper plugin folder. Overrides REXTIO_MAPPER_PATHS and [mappers] paths.",
    )
    parser.add_argument(
        "--enable-mapper",
        action="append",
        default=None,
        dest="mapper_enabled",
        help="Mapper plugin id to enable. Overrides REXTIO_MAPPERS_ENABLED and [mappers] enabled.",
    )
    parser.add_argument(
        "--mapper-repository",
        default=None,
        help=(
            "Public Git mapper repository URL. Overrides REXTIO_MAPPER_REPOSITORY "
            "and [mappers] repository."
        ),
    )


def _add_policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--native-marker",
        choices=("auto", "decorator"),
        default=None,
        help="Native discovery policy. Overrides REXTIO_NATIVE_MARKER and [policy] native_marker.",
    )
    parser.add_argument(
        "--require-type-hints",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Require type hints. Overrides REXTIO_REQUIRE_TYPE_HINTS and [policy] require_type_hints.",
    )
    parser.add_argument(
        "--allow-dynamic-features",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Allow dynamic Python features. Overrides REXTIO_ALLOW_DYNAMIC_FEATURES and "
            "[policy] allow_dynamic_features."
        ),
    )
    parser.add_argument(
        "--boundary-warnings",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Emit boundary warnings. Overrides REXTIO_BOUNDARY_WARNINGS and [policy] boundary_warnings.",
    )
    parser.add_argument(
        "--native-top-level",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Try native conversion for supported module top-level logic. Overrides "
            "REXTIO_NATIVE_TOP_LEVEL and [policy] native_top_level."
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
