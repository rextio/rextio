from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: str
    message: str
    file_path: str
    line: int | None = None
    column: int | None = None
    function_name: str | None = None
    suggestion: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "function_name": self.function_name,
            "suggestion": self.suggestion,
        }
