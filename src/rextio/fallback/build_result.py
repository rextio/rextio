from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FallbackBuildResult:
    status: str
    backend: str
    message: str
    command: list[list[str]] = field(default_factory=list)
    compiled_artifacts: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "backend": self.backend,
            "message": self.message,
            "command": [list(command) for command in self.command],
            "compiled_artifacts": list(self.compiled_artifacts),
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def cpython_fallback_build_result() -> FallbackBuildResult:
    return FallbackBuildResult(
        status="built",
        backend="cpython",
        message="CPython fallback package tree was copied.",
    )

