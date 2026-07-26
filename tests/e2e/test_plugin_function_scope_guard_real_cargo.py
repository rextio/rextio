"""E2E: Core-generated crate emits API 1.7 guards; Drop runs on ok and early Err.

Uses ``generate_rust_crate_module`` with an authorized StandalonePluginContext
and an API-1.7 provider. A temporary-file Drop probe (no global/TLS) proves
exactly one enter/drop pair per successful invocation and per early Result
error path without any explicit keepalive of the guard binding.
"""

from __future__ import annotations

import os
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
    Claimed,
    ClaimSite,
    CoverageDecl,
    CrateDependency,
    LoweredExpr,
    LoweringContext,
    PluginArtifactCapability,
    PluginArtifactTypeSupport,
    PluginFunctionScopeContext,
    PluginFunctionScopeGuard,
    PluginType,
    RuleRecord,
    RuleScope,
    BoundaryConversion,
)
from rextio.plugins.capabilities import (
    StandalonePluginContext,
    resolve_provider_artifact_capability,
)
from rextio.plugins.models import RextioPlugin

# Auto-tagged needs_cargo by tests/e2e/conftest.py (stem ends with _real_cargo).
pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not available")

PLUGIN_ID = "rextio-demo"
TYPE_KEY = "rextio-demo/scalar"
RULE_OK = "rextio-demo/ok"
RULE_ERR = "rextio-demo/err"

PROBE_HELPER = """\
struct ProbeGuard;
impl ProbeGuard {
    fn enter() -> Self {
        use std::io::Write;
        if let Ok(path) = std::env::var("REXTIO_SCOPE_GUARD_PROBE") {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| writeln!(f, "enter"));
        }
        Self
    }
}
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        use std::io::Write;
        if let Ok(path) = std::env::var("REXTIO_SCOPE_GUARD_PROBE") {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| writeln!(f, "drop"));
        }
    }
}
"""


class ScopeGuardCargoProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.7"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(
            id=PLUGIN_ID,
            name="Demo",
            api_version="1.7",
            lowering_provided=True,
            function_scope_guard_declared=True,
        )

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("demo",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (
            RuleRecord(
                id=RULE_OK,
                provider=PLUGIN_ID,
                scope=RuleScope(kind="call", pattern="demo.ok"),
                constraint="ok",
                outcome="native",
                diagnostic_code="RXTP-DEMO-001",
                guidance="g",
                stability="experimental",
            ),
            RuleRecord(
                id=RULE_ERR,
                provider=PLUGIN_ID,
                scope=RuleScope(kind="call", pattern="demo.err"),
                constraint="err",
                outcome="native",
                diagnostic_code="RXTP-DEMO-002",
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
        if site.target == "demo.ok":
            return Claimed(rule_id=RULE_OK, result_type=TYPE_KEY)
        if site.target == "demo.err":
            return Claimed(rule_id=RULE_ERR, result_type=TYPE_KEY)
        return Claimed(rule_id=RULE_OK, result_type=TYPE_KEY)

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        assert ctx.function_scope_guard_active is True
        # Expression-only: early error via nested return inside a block, so
        # Drop of the let-bound guard still runs on the Err path.
        if site.rule_id == RULE_ERR:
            return LoweredExpr(
                rust=(
                    f"{{ if {ctx.operands[0]} < 0 {{ "
                    f'return Err(RextioError::new("ValueError", "neg")); '
                    f"}} {ctx.operands[0]} * 2 }}"
                )
            )
        return LoweredExpr(rust=f"({ctx.operands[0]} * 2)")

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        return ()

    def artifact_capability(self, profile):
        if profile.kind is not ArtifactKind.RUST_CRATE:
            return None
        return PluginArtifactCapability(
            rule_ids=(RULE_OK, RULE_ERR),
            types=(
                PluginArtifactTypeSupport(
                    type_key=TYPE_KEY,
                    helpers=(PROBE_HELPER,),
                ),
            ),
        )

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        assert ctx.backend == "standalone-rust"
        assert ctx.has_python_boundary_calls is False
        # Helpers are declared only on the authorized capability type support;
        # the guard declaration itself is just the zero-arg path call.
        return PluginFunctionScopeGuard(rust="ProbeGuard::enter()")


def _function(name: str, target: str, rule_id: str) -> FunctionIR:
    rxt = RxtPluginType(key=TYPE_KEY, native_rust="i64")
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id=rule_id,
        kind="call",
        target=target,
        operand_types=(TYPE_KEY,),
        result_type=TYPE_KEY,
    )
    return FunctionIR(
        name=name,
        qualname=f"kernels.{name}",
        module_name="kernels",
        params=[ParamIR("x", rxt)],
        return_type=rxt,
        body=BlockIR(
            statements=[ReturnIR(value=CallIR(function=target, args=[NameIR(id="x")], claim=claim))]
        ),
        plugin_lowered=True,
    )


def test_generated_crate_guard_drop_on_ok_and_early_error(tmp_path: Path) -> None:
    provider = ScopeGuardCargoProvider()
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    capability = resolve_provider_artifact_capability(PLUGIN_ID, provider, "1.7", profile)
    assert capability is not None
    ok_fn = _function("ok_path", "demo.ok", RULE_OK)
    err_fn = _function("err_path", "demo.err", RULE_ERR)
    source = generate_rust_crate_module(
        ModuleIR(functions=[ok_fn, err_fn]),
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key={TYPE_KEY: RxtPluginType(key=TYPE_KEY, native_rust="i64")},
        standalone=StandalonePluginContext(
            profile=profile,
            capabilities={PLUGIN_ID: capability},
            capable_qualnames=frozenset({"kernels.ok_path", "kernels.err_path"}),
        ),
    )
    # Core emitted the let-bound guard without an explicit keepalive of that binding.
    assert "let __rextio_plugin_scope_guard_0 = ProbeGuard::enter();" in source
    assert "let _ = &__rextio_plugin_scope_guard_" not in source
    assert "let _ = __rextio_plugin_scope_guard_" not in source

    crate_dir = tmp_path / "crate"
    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True)
    # Keep Core's importable dependency pins (base64/sha2/…), but emit a binary
    # package so we can run the generated functions under a Drop probe.
    cargo_toml = render_importable_cargo_toml("rextio_scope_guard_demo")
    cargo_toml = cargo_toml.replace(
        '[lib]\nname = "rextio_scope_guard_demo"\n',
        '[[bin]]\nname = "rextio_scope_guard_demo"\npath = "src/main.rs"\n',
    )
    (crate_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    (src_dir / "main.rs").write_text(
        source
        + """

fn main() {
    // Success path: one enter + one drop.
    assert_eq!(kernels__ok_path(3).unwrap(), 6);
    // Early error path: still exactly one enter + one drop (Drop on Err).
    assert!(kernels__err_path(-1).is_err());
    // Two successes => two enter/drop pairs (one guard per invocation).
    assert_eq!(kernels__ok_path(1).unwrap(), 2);
    assert_eq!(kernels__ok_path(2).unwrap(), 4);
}
""",
        encoding="utf-8",
    )

    probe = tmp_path / "probe.log"
    env = os.environ.copy()
    env["REXTIO_SCOPE_GUARD_PROBE"] = str(probe)
    if probe.exists():
        probe.unlink()

    result = subprocess.run(
        ["cargo", "run", "--quiet", "--manifest-path", str(crate_dir / "Cargo.toml")],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=crate_dir,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = probe.read_text(encoding="utf-8").splitlines()
    # main: ok, err, ok, ok => 4 enter/drop pairs.
    assert lines == ["enter", "drop"] * 4
