from __future__ import annotations

import importlib
import inspect
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import GenericAlias
from typing import Any, get_args, get_origin, get_type_hints

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import BuildResult, build_hybrid_artifact
from rextio.config.loader import ConfigError, load_config
from rextio.fallback.module_copy import fallback_module_name
from rextio.targets.plan import TargetPlanError, create_target_plan


@dataclass(frozen=True)
class BenchResult:
    target: str
    fallback_ms: float
    native_ms: float
    speedup: float
    iterations: int
    build_result: BuildResult

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "iterations": self.iterations,
            "fallback_ms": self.fallback_ms,
            "native_ms": self.native_ms,
            "speedup": self.speedup,
            "build": self.build_result.to_dict(),
        }


def run_benchmark(project_root: Path, target: str, iterations: int = 1000) -> BenchResult:
    try:
        config = load_config(project_root, environ=os.environ)
        target_plan = create_target_plan(project_root, config)
    except (ConfigError, TargetPlanError) as exc:
        raise BenchError(f"configuration error: {exc}") from exc
    analysis = analyze_project(
        project_root,
        boundary_warnings=config.policy.boundary_warnings,
        native_marker=config.policy.native_marker,
        target_language=target_plan.spec.language,
        native_top_level=config.policy.native_top_level,
    )
    function = _find_target(analysis, target)
    if function is None:
        raise BenchError(f"target function was not found: {target}")
    if not function.accepted:
        raise BenchError(f"target function is not accepted for native compilation: {target}")

    build_result = build_hybrid_artifact(
        project_root,
        analysis,
        fallback="cpython",
        build_tool=config.rust.build_tool,
        target_plan=target_plan,
    )
    if build_result.native_build.status != "built":
        raise BenchError(build_result.native_build.message)

    _prepend_sys_path(build_result.layout.build_python_dir)
    wrapper_func = _import_function(function.module_name, function.name)
    fallback_func = _import_function(_fallback_import_name(analysis, function), function.name)
    args = _sample_args(fallback_func)
    fallback_result = fallback_func(*args)
    native_result = wrapper_func(*args)
    if fallback_result != native_result:
        raise BenchError(
            f"native result did not match fallback result for {target}: "
            f"{native_result!r} != {fallback_result!r}"
        )

    fallback_ms = _time_call(fallback_func, args, iterations)
    native_ms = _time_call(wrapper_func, args, iterations)
    speedup = fallback_ms / native_ms if native_ms > 0 else float("inf")
    return BenchResult(
        target=target,
        fallback_ms=fallback_ms,
        native_ms=native_ms,
        speedup=speedup,
        iterations=iterations,
        build_result=build_result,
    )


class BenchError(RuntimeError):
    pass


def _find_target(analysis: ProjectAnalysis, target: str) -> FunctionAnalysis | None:
    for function in analysis.native_candidates:
        if function.qualname == target:
            return function
    return None


def _fallback_import_name(analysis: ProjectAnalysis, function: FunctionAnalysis) -> str:
    module = analysis.module_for_function(function)
    if module is None:
        raise BenchError(f"module was not found for target: {function.qualname}")
    fallback_name = fallback_module_name(module)
    if Path(module.file_path).name == "__init__.py":
        return f"{module.module_name}.{fallback_name}"
    if "." not in module.module_name:
        return fallback_name
    package = module.module_name.rsplit(".", 1)[0]
    return f"{package}.{fallback_name}"


def _prepend_sys_path(path: Path) -> None:
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)
    importlib.invalidate_caches()


def _import_function(module_name: str, function_name: str) -> Any:
    module = importlib.import_module(module_name)
    return getattr(module, function_name)


def _sample_args(function: Any) -> tuple[object, ...]:
    signature = inspect.signature(function)
    hints = get_type_hints(function)
    args: list[object] = []
    for name, parameter in signature.parameters.items():
        if parameter.default is not inspect.Parameter.empty:
            continue
        args.append(_sample_value(hints.get(name, parameter.annotation)))
    return tuple(args)


def _sample_value(annotation: object) -> object:
    if annotation is inspect.Parameter.empty:
        raise BenchError("benchmark target has an unannotated required parameter")
    if annotation is int:
        return 42
    if annotation is float:
        return 42.0
    if annotation is bool:
        return True
    if annotation is str:
        return "rextio"
    origin = get_origin(annotation)
    if origin is list or isinstance(annotation, GenericAlias):
        item_type = get_args(annotation)[0]
        if item_type is int:
            return list(range(1000))
        if item_type is float:
            return [float(index) for index in range(1000)]
        if item_type is bool:
            return [index % 2 == 0 for index in range(1000)]
        if item_type is str:
            return [f"value_{index}" for index in range(1000)]
    raise BenchError(f"unsupported benchmark parameter type: {annotation!r}")


def _time_call(function: Any, args: tuple[object, ...], iterations: int) -> float:
    for _ in range(3):
        function(*args)
    start = time.perf_counter()
    for _ in range(iterations):
        function(*args)
    elapsed = time.perf_counter() - start
    return elapsed * 1000.0 / iterations
