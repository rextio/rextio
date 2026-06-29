from __future__ import annotations

import argparse
import math
import warnings
from collections.abc import Sequence

from rextio.limits import MAX_BUILD_TIMEOUT_SECONDS
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
    _add_output_options(init_parser)
    init_parser.set_defaults(handler=init_cmd.run)

    check_parser = subparsers.add_parser("check", help="Analyze native candidates.")
    check_parser.add_argument("project_root", nargs="?", default=".", help="Project root to check.")
    check_parser.add_argument("--json", action="store_true", help="Print structured JSON.")
    check_parser.add_argument(
        "--no-report",
        action="store_true",
        help="Do not write .rextio/reports/check.json (keep the command side-effect-free).",
    )
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
    _add_import_options(check_parser)
    _add_jit_options(check_parser)
    _add_policy_options(check_parser)
    _add_output_options(check_parser)
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
    _add_import_options(build_parser_)
    _add_jit_options(build_parser_)
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
        "--build-timeout",
        type=_positive_number,
        default=None,
        help=(
            "Per-invocation timeout (seconds) for external build tools "
            "(cargo/maturin/nuitka). Overrides REXTIO_BUILD_TIMEOUT and "
            "[build] build_timeout_seconds."
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
    _add_rust_crate_options(build_parser_)
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
    _add_output_options(build_parser_)
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
    _add_import_options(generate_parser)
    _add_jit_options(generate_parser)
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
    _add_rust_crate_options(generate_parser)
    generate_parser.add_argument(
        "--nuitka-fallback",
        choices=("experimental",),
        default=None,
        help="Nuitka fallback policy. Overrides REXTIO_NUITKA_FALLBACK and [fallback] nuitka.",
    )
    _add_policy_options(generate_parser)
    _add_output_options(generate_parser)
    generate_parser.set_defaults(handler=generate_cmd.run)

    bench_parser = subparsers.add_parser("bench", help="Benchmark a specific function.")
    bench_parser.add_argument("target", help="Fully qualified function name.")
    bench_parser.add_argument("--project-root", default=".", help="Project root to benchmark.")
    _add_output_options(bench_parser)
    bench_parser.set_defaults(handler=bench_cmd.run)

    clean_parser = subparsers.add_parser("clean", help="Remove generated Rextio artifacts.")
    clean_parser.add_argument("project_root", nargs="?", default=".", help="Project root to clean.")
    _add_output_options(clean_parser)
    clean_parser.set_defaults(handler=clean_cmd.run)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Python hides DeprecationWarning under default filters, so Rextio's own
    # deprecations (e.g. a plugin's legacy `rules` field) would never reach a CLI
    # user. Surface ours — they print to stderr — without unmuting third-party noise.
    warnings.filterwarnings("default", category=DeprecationWarning, module=r"rextio\..*")
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


def _positive_number(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a finite positive number") from exc
    # `float()` accepts "inf"/"nan"; reject them so the timeout stays meaningful.
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    if parsed > MAX_BUILD_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(f"must be at most {MAX_BUILD_TIMEOUT_SECONDS} seconds")
    return parsed


def _key_value(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("must use KEY=VALUE")
    key, option_value = value.split("=", 1)
    if not key:
        raise argparse.ArgumentTypeError("must not use an empty key")
    return key, option_value


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default=None,
        help="Output format for the command result. Defaults to text.",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Emit extra progress detail on stdout.",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress output; keep the result and errors.",
    )


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
        "--enable-plugin",
        action="append",
        default=None,
        dest="plugin_enabled",
        help="Installed Rextio plugin id to enable. Overrides REXTIO_PLUGINS_ENABLED and [plugins] enabled.",
    )


def _add_import_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--default-external-policy",
        choices=("fallback", "analyze", "try-native"),
        default=None,
        help=(
            "Default policy for external Python packages without an active Rextio plugin. "
            "Overrides REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY and [imports] default_external_policy."
        ),
    )
    parser.add_argument(
        "--package-import-policy",
        action="append",
        default=None,
        metavar="PACKAGE=POLICY",
        type=_key_value,
        help=(
            "Per-package import policy, where POLICY is fallback, analyze, plugin, or try-native. "
            "May be passed more than once. Overrides REXTIO_IMPORTS_PACKAGES and [imports.packages]."
        ),
    )


def _add_jit_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--jit",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable experimental native-side JIT. Overrides REXTIO_JIT and [jit] enabled.",
    )
    parser.add_argument(
        "--jit-backend",
        choices=("cranelift",),
        default=None,
        help="Experimental JIT backend. Overrides REXTIO_JIT_BACKEND and [jit] backend.",
    )
    parser.add_argument(
        "--jit-hot-threshold",
        type=_non_negative_int,
        default=None,
        help=(
            "Calls before an experimental JIT candidate is compiled. "
            "Overrides REXTIO_JIT_HOT_THRESHOLD and [jit] hot_threshold."
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


def _add_rust_crate_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rust-importable",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Generate a Rust library crate that Rust projects can import as a path dependency. "
            "Overrides REXTIO_RUST_IMPORTABLE and [rust] importable."
        ),
    )
    parser.add_argument(
        "--rust-crate-name",
        default=None,
        help=(
            "Cargo package name for the Rust-importable crate. Overrides "
            "REXTIO_RUST_CRATE_NAME and [rust] crate_name."
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
