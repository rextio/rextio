"""Positive vertical slice: API 1.4 plugin lowers into a standalone Rust crate.

Generates a boundary-free crate (no PyO3) with declared type/rule/support/
dependency and compiles it with cargo. Exercises backend/profile-aware
lowering and profile-specific dependency injection into the Cargo manifest.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from rextio.artifacts.models import ArtifactKind
from rextio.artifacts.profiles import rust_crate_profile
from rextio.codegen.rust.cargo import render_importable_cargo_toml
from rextio.codegen.rust.generator import generate_rust_crate_module
from rextio.config.schema import RextioConfig
from rextio.ir.nodes import (
    BlockIR,
    CallIR,
    FunctionIR,
    ModuleIR,
    NameIR,
    ParamIR,
    PluginClaimIR,
    ReturnIR,
)
from rextio.ir.types import RxtPluginType
from rextio.plugins.api import (
    LOWERING_BACKEND_STANDALONE_RUST,
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CoverageDecl,
    CrateDependency,
    LoweredExpr,
    LoweringContext,
    PluginArtifactCapability,
    PluginArtifactTypeSupport,
    PluginType,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.capabilities import (
    StandalonePluginContext,
    resolve_provider_artifact_capability,
)
from rextio.plugins.models import RextioPlugin

pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not available")

PLUGIN_ID = "rextio-demo"
TYPE_KEY = "rextio-demo/scalar"
RULE_ID = "rextio-demo/double"


class StandaloneCargoProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.4"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id=PLUGIN_ID, name="Demo", api_version="1.4", lowering_provided=True)

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("demo",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (
            RuleRecord(
                id=RULE_ID,
                provider=PLUGIN_ID,
                scope=RuleScope(kind="call", pattern="demo.double"),
                constraint="double",
                outcome="native",
                diagnostic_code="RXTP-DEMO-001",
                guidance="g",
                stability="experimental",
            ),
        )

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (
            PluginType(
                key=TYPE_KEY,
                annotations=("demo_types.Scalar",),
                rust_type="i64",
                conversion=BoundaryConversion(
                    param_rust="i64",
                    param_expr="{param}",
                    return_rust="i64",
                    return_expr="{value}",
                ),
            ),
        )

    def claim(self, site: ClaimSite, config: RextioConfig):
        return Claimed(rule_id=RULE_ID, result_type=TYPE_KEY)

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        # Profile/backend-aware: standalone must not emit PyO3-only symbols.
        if ctx.backend == LOWERING_BACKEND_STANDALONE_RUST:
            assert ctx.artifact_profile is not None
            assert ctx.artifact_profile.kind is ArtifactKind.RUST_CRATE
            return LoweredExpr(
                rust=f"demo_scale({ctx.operands[0]})",
                uses=("use demo_support::scale;",),
                helpers=("fn demo_scale(x: i64) -> i64 { x * 2 }",),
            )
        return LoweredExpr(
            rust=f"pyo3::Python::with_gil(|_| {ctx.operands[0]})",
            uses=("use pyo3::prelude::*;",),
        )

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        # Host-extension surface — must NOT appear in standalone Cargo.toml.
        return (CrateDependency(name="host_only_dep", version="=9.9.9"),)

    def artifact_capability(self, profile):
        if profile.kind is not ArtifactKind.RUST_CRATE:
            return None
        return PluginArtifactCapability(
            rule_ids=(RULE_ID,),
            types=(
                PluginArtifactTypeSupport(
                    type_key=TYPE_KEY,
                    uses=("use demo_support::scale;",),
                    helpers=("fn demo_scale(x: i64) -> i64 { x * 2 }",),
                ),
            ),
            # Profile-specific dep distinct from host crate_dependencies().
            crate_dependencies=(CrateDependency(name="demo_support", version="=0.1.0"),),
        )


def test_standalone_plugin_crate_compiles_without_pyo3(tmp_path: Path) -> None:
    provider = StandaloneCargoProvider()
    rxt_type = RxtPluginType(key=TYPE_KEY, native_rust="i64")
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id=RULE_ID,
        kind="call",
        target="demo.double",
        operand_types=(TYPE_KEY,),
        result_type=TYPE_KEY,
    )
    function = FunctionIR(
        name="double",
        qualname="kernels.double",
        module_name="kernels",
        params=[ParamIR("x", rxt_type)],
        return_type=rxt_type,
        body=BlockIR(
            statements=[
                ReturnIR(
                    value=CallIR(
                        function="demo.double",
                        args=[NameIR(id="x")],
                        claim=claim,
                    )
                )
            ]
        ),
        plugin_lowered=True,
    )
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    capability = resolve_provider_artifact_capability(PLUGIN_ID, provider, "1.4", profile)
    assert capability is not None
    # Profile-specific deps from capability, not host crate_dependencies().
    from rextio.plugins.capabilities import profile_crate_dependencies

    extra_deps = profile_crate_dependencies({PLUGIN_ID: capability}, {PLUGIN_ID})
    assert any(name == "demo_support" for name, _ver, _feat in extra_deps)
    assert all(name != "host_only_dep" for name, _ver, _feat in extra_deps)

    source = generate_rust_crate_module(
        ModuleIR(functions=[function]),
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key={TYPE_KEY: rxt_type},
        standalone=StandalonePluginContext(
            profile=profile,
            capabilities={PLUGIN_ID: capability},
            capable_qualnames=frozenset({"kernels.double"}),
        ),
    )
    assert "pyo3" not in source.lower()
    assert "demo_scale" in source
    assert "use demo_support::scale;" in source

    crate_dir = tmp_path / "crate"
    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True)
    # Inject a local path crate so cargo resolves demo_support without crates.io.
    support_dir = tmp_path / "demo_support"
    (support_dir / "src").mkdir(parents=True)
    (support_dir / "Cargo.toml").write_text(
        '[package]\nname = "demo_support"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (support_dir / "src" / "lib.rs").write_text(
        "pub fn scale(x: i64) -> i64 { x }\n",
        encoding="utf-8",
    )
    cargo_toml = render_importable_cargo_toml(
        "rextio_standalone_demo",
        extra_dependencies=extra_deps,
    )
    # Rewrite exact-version pin to a path dependency for offline cargo.
    cargo_toml = cargo_toml.replace(
        'demo_support = "=0.1.0"',
        f'demo_support = {{ path = "{support_dir}" }}',
    )
    assert "demo_support" in cargo_toml
    assert "host_only_dep" not in cargo_toml
    # No pyo3 dependency line (comments may mention pyo3 for edition notes).
    assert 'pyo3 =' not in cargo_toml
    assert "pyo3 = {" not in cargo_toml
    (crate_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    (src_dir / "lib.rs").write_text(source, encoding="utf-8")

    result = subprocess.run(
        ["cargo", "check", "--manifest-path", str(crate_dir / "Cargo.toml")],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
