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
            f"default_equals cannot compare {type(left).__name__} results; "
            "pass a custom equals= comparator"
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
    ) -> EquivalenceChecker:
        """Return a checker for one generated function (``pkg.module.func``)."""
        module_name, _, function_name = qualname.rpartition(".")
        if not module_name:
            raise ValueError(f"qualname must be package-qualified: {qualname!r}")
        return EquivalenceChecker(
            project=self,
            module_name=module_name,
            function_name=function_name,
            equals=equals if equals is not None else default_equals,
        )


@dataclass
class EquivalenceChecker:
    """Calls one function natively and on the fallback and compares the legs."""

    project: CertifiedProject
    module_name: str
    function_name: str
    equals: Callable[[object, object], bool]

    def __call__(self, *args: object) -> object:
        """Run both legs on deep copies of ``args`` and return the native result.

        When both legs raise equivalently (same type and message), the native
        exception is re-raised: agreement on an error is certified behavior.
        A divergence of any kind raises :class:`CertificationError`.
        """
        native_outcome = self._run("native", args)
        fallback_outcome = self._run("fallback", args)
        self._compare(native_outcome, fallback_outcome, args)
        kind, value = native_outcome
        if kind == "raised":
            # Both legs raised equivalently - that IS the agreed behavior;
            # surface it so the caller can assert on (or filter) it.
            assert isinstance(value, Exception)
            raise value
        return value

    def _site(self) -> str:
        return f"{self.module_name}.{self.function_name}"

    def _run(self, mode: str, args: tuple[object, ...]) -> tuple[str, object]:
        function = self._load_function()
        previous = os.environ.get("REXTIO_NATIVE_MODE")
        os.environ["REXTIO_NATIVE_MODE"] = mode
        try:
            return ("returned", function(*copy.deepcopy(args)))
        except Exception as exc:
            return ("raised", exc)
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
