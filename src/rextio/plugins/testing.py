"""The plugin certification kit: native<->fallback equivalence testing.

The reusable harness from docs/specs/plugin-lowering.md section 6. A plugin
builds a fixture project once, then drives each (hypothesis-generated) input
through the generated wrapper twice — once forced native, once forced
fallback — and asserts the results are equivalent:

    project = build_certification_project(fixture_root)
    dot = project.equivalence_checker("np_app.kernels.dot")

    @given(arrays(...), arrays(...))
    def test_dot_matches_python(a, b):
        dot(a, b)

Core stays dependency-free: the default comparator handles scalars (with
NaN == NaN for floats); plugins whose functions return richer values (e.g.
numpy arrays) pass their own ``equals``. Arguments are deep-copied per call so
one leg's accidental mutation cannot leak into the other, and both legs'
exceptions are compared by type and message when a call raises.
"""

from __future__ import annotations

import copy
import importlib
import json
import math
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


class CertificationError(AssertionError):
    """Raised when the native and fallback results diverge."""


def default_equals(left: object, right: object) -> bool:
    """Compare two results: ``==`` with NaN-equality for floats.

    Raises :class:`CertificationError` when ``==`` does not produce a plain
    bool (e.g. numpy arrays) — pass a custom ``equals`` for such types.
    """
    if isinstance(left, float) and isinstance(right, float):
        if math.isnan(left) and math.isnan(right):
            return True
        return left == right and math.copysign(1.0, left) == math.copysign(1.0, right)
    if type(left) is not type(right):
        return False
    result = left == right
    if not isinstance(result, bool):
        raise CertificationError(
            f"default_equals cannot compare {type(left).__name__} == "
            f"{type(right).__name__}: the comparison returned "
            f"{type(result).__name__}, not bool; pass a custom equals= comparator"
        )
    return result


def build_certification_project(
    project_root: str | Path,
    *,
    build_args: tuple[str, ...] = ("--fallback=cpython",),
) -> CertifiedProject:
    """Build the fixture project once and return the certification handle.

    Runs ``rextio build`` on the fixture and asserts the native module was
    actually built — an equivalence test against a fallback-only build would
    vacuously pass.
    """
    from rextio.cli.main import main

    root = Path(project_root).resolve()
    exit_code = main(["build", str(root), *build_args])
    report_path = root / ".rextio" / "reports" / "build.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    if exit_code != 0:
        raise CertificationError(f"rextio build failed for {root} (exit {exit_code}): {report.get('status')}")
    native_build = report.get("native_build") or {}
    if native_build.get("status") != "built":
        raise CertificationError(
            f"certification requires a built native module; got {native_build.get('status')!r}"
        )
    return CertifiedProject(project_root=root)


@dataclass(frozen=True)
class CertifiedProject:
    """A built fixture project the certification checkers run against."""

    project_root: Path

    @property
    def build_python_dir(self) -> Path:
        """The generated import-compatible package tree."""
        return self.project_root / ".rextio" / "build" / "python"

    def equivalence_checker(
        self,
        qualname: str,
        *,
        equals: Callable[[object, object], bool] | None = None,
        args_equals: Callable[[object, object], bool] | None = None,
        copy_args: Callable[[tuple[object, ...]], tuple[object, ...]] | None = None,
    ) -> EquivalenceChecker:
        """Return a checker for one generated function (``pkg.module.func``).

        Refuses functions that are not actually served natively: for a
        fallback-only (or shim) symbol both legs would execute the same
        Python implementation and every equivalence check would pass
        vacuously.

        ``args_equals`` (optional) additionally compares each argument's
        post-call state between the legs — catching divergences the return
        value cannot show, e.g. a fallback that mutates an argument in place
        while the native leg leaves its copy untouched.

        ``copy_args`` (optional) replaces the per-leg ``copy.deepcopy`` when
        the input's representation matters: deepcopy normalizes e.g. a
        strided numpy view to a fresh contiguous array, silently changing
        what actually crosses the boundary.
        """
        module_name, _, function_name = qualname.rpartition(".")
        if not module_name:
            raise ValueError(f"qualname must be package-qualified: {qualname!r}")
        self._assert_natively_served(qualname)
        return EquivalenceChecker(
            project=self,
            module_name=module_name,
            function_name=function_name,
            equals=equals if equals is not None else default_equals,
            args_equals=args_equals,
            copy_args=copy_args,
        )

    def _assert_natively_served(self, qualname: str) -> None:
        report_path = self.project_root / ".rextio" / "reports" / "check.json"
        if not report_path.exists():
            raise CertificationError(
                f"missing analysis report {report_path}; build the project first"
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for module in report.get("modules", ()):
            for function in module.get("functions", ()):
                if function.get("qualname") != qualname:
                    continue
                route = str(function.get("route", ""))
                if function.get("native_status") == "accepted" and (
                    route == "native-direct" or route.startswith("native-plugin:")
                ):
                    return
                raise CertificationError(
                    f"{qualname} is not natively served (native_status="
                    f"{function.get('native_status')!r}, route={route!r}); "
                    "certifying it would compare the fallback against itself"
                )
        raise CertificationError(f"{qualname} was not found in {report_path}")


@dataclass
class EquivalenceChecker:
    """Calls one function natively and on the fallback and compares the legs."""

    project: CertifiedProject
    module_name: str
    function_name: str
    equals: Callable[[object, object], bool]
    args_equals: Callable[[object, object], bool] | None = None
    # Per-leg argument copier (default: copy.deepcopy). deepcopy isolates the
    # legs but can NORMALIZE the value's representation - e.g. a strided
    # (non-contiguous) numpy view deep-copies to a fresh C-contiguous array -
    # so inputs whose REPRESENTATION is the scenario under test need a custom
    # copier that reconstructs it (council round 4: the non-contiguous
    # certification was vacuous under deepcopy).
    copy_args: Callable[[tuple[object, ...]], tuple[object, ...]] | None = None

    def __call__(self, *args: object) -> object:
        """Run both legs on deep copies of ``args`` and return the native result.

        When both legs raise equivalently (same type and message), the native
        exception is re-raised: agreement on an error is certified behavior.
        A divergence of any kind raises :class:`CertificationError`.
        """
        native_outcome, native_args = self._run("native", args)
        fallback_outcome, fallback_args = self._run("fallback", args)
        self._compare(native_outcome, fallback_outcome, args)
        self._compare_args(native_args, fallback_args, args)
        kind, value = native_outcome
        if kind == "raised":
            # Both legs raised equivalently - that IS the agreed behavior;
            # surface it so the caller can assert on (or filter) it.
            assert isinstance(value, Exception)
            raise value
        return value

    def _site(self) -> str:
        return f"{self.module_name}.{self.function_name}"

    def _run(
        self, mode: str, args: tuple[object, ...]
    ) -> tuple[tuple[str, object], tuple[object, ...]]:
        # The mode is exported BEFORE the module import: generated native
        # top-level initialization is selected at import time
        # (_rextio_select_fallback_module), so importing first would let the
        # fallback leg observe natively-initialized module state (council
        # round 4).
        previous = os.environ.get("REXTIO_NATIVE_MODE")
        os.environ["REXTIO_NATIVE_MODE"] = mode
        try:
            function = self._load_function()
            copier = self.copy_args if self.copy_args is not None else copy.deepcopy
            call_args = tuple(copier(args))
            try:
                return ("returned", function(*call_args)), call_args
            except Exception as exc:
                return ("raised", exc), call_args
        finally:
            if previous is None:
                os.environ.pop("REXTIO_NATIVE_MODE", None)
            else:
                os.environ["REXTIO_NATIVE_MODE"] = previous

    def _load_function(self) -> Callable[..., object]:
        build_dir = str(self.project.build_python_dir)
        inserted = build_dir not in sys.path
        self._evict_modules()
        if inserted:
            sys.path.insert(0, build_dir)
        try:
            module = importlib.import_module(self.module_name)
            loaded_from = getattr(module, "__file__", "") or ""
            if not loaded_from.startswith(str(self.project.build_python_dir)):
                raise CertificationError(
                    f"module {self.module_name!r} was imported from {loaded_from!r}, not the "
                    "generated build tree; remove conflicting entries from sys.path/sys.modules"
                )
            return getattr(module, self.function_name)
        finally:
            if inserted:
                sys.path.remove(build_dir)
            # Leave no trace: the generated native extension is always named
            # _rextio_native, so a cached module from ANOTHER built project
            # (e.g. an earlier test in the same session) would be silently
            # reused by this project's wrappers - and ours would poison the
            # next. Evict on the way in and on the way out.
            self._evict_modules()

    def _evict_modules(self) -> None:
        package_root = self.module_name.split(".")[0]
        for name in list(sys.modules):
            if (
                name == "_rextio_native"
                or name == package_root
                or name.startswith(f"{package_root}.")
            ):
                sys.modules.pop(name, None)

    def _compare(
        self,
        native: tuple[str, object],
        fallback: tuple[str, object],
        args: tuple[object, ...],
    ) -> None:
        native_kind, native_value = native
        fallback_kind, fallback_value = fallback
        if native_kind != fallback_kind:
            raise CertificationError(
                f"{self._site()} diverged for args {args!r}: native {native_kind} "
                f"{native_value!r}, fallback {fallback_kind} {fallback_value!r}"
            )
        if native_kind == "raised":
            assert isinstance(native_value, Exception)
            assert isinstance(fallback_value, Exception)
            if type(native_value) is not type(fallback_value) or str(native_value) != str(
                fallback_value
            ):
                raise CertificationError(
                    f"{self._site()} raised differently for args {args!r}: native "
                    f"{native_value!r}, fallback {fallback_value!r}"
                )
            return
        if not self.equals(native_value, fallback_value):
            raise CertificationError(
                f"{self._site()} results diverged for args {args!r}: native "
                f"{native_value!r}, fallback {fallback_value!r}"
            )

    def _compare_args(
        self,
        native_args: tuple[object, ...],
        fallback_args: tuple[object, ...],
        args: tuple[object, ...],
    ) -> None:
        if self.args_equals is None:
            return
        for index, (native_arg, fallback_arg) in enumerate(
            zip(native_args, fallback_args)
        ):
            if not self.args_equals(native_arg, fallback_arg):
                raise CertificationError(
                    f"{self._site()} argument {index} diverged after the call for "
                    f"args {args!r}: native leg left {native_arg!r}, fallback leg "
                    f"left {fallback_arg!r}"
                )
