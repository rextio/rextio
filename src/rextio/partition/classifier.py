"""Classification of each function as native or fallback."""

from __future__ import annotations

from typing import Literal

from rextio.analyzer.models import FunctionAnalysis

FunctionPartition = Literal["native", "fallback"]


def classify_function(function: FunctionAnalysis) -> FunctionPartition:
    """Classify a function into its build partition (native or fallback)."""
    if function.is_native_candidate and function.accepted:
        return "native"
    return "fallback"
