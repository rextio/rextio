from __future__ import annotations

import enum
import json
import sys
from argparse import Namespace
from typing import IO


class Verbosity(enum.IntEnum):
    """How much non-essential output the CLI emits."""

    QUIET = 0
    NORMAL = 1
    VERBOSE = 2


class Reporter:
    """Routes CLI output: human text to stdout, diagnostics to stderr.

    A command's *primary result* goes to stdout via :meth:`print_result` (rendered
    as text or, with ``--format=json``, as JSON). Progress/status lines go through
    :meth:`info`/:meth:`detail` and are suppressed by ``--quiet`` (and in JSON mode,
    so JSON stdout stays machine-parseable). Warnings and errors always go to stderr.
    """

    def __init__(
        self,
        *,
        verbosity: Verbosity = Verbosity.NORMAL,
        output_format: str = "text",
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
    ) -> None:
        self.verbosity = verbosity
        self.output_format = output_format
        self._stdout = stdout if stdout is not None else sys.stdout
        self._stderr = stderr if stderr is not None else sys.stderr

    @classmethod
    def from_args(cls, args: Namespace) -> Reporter:
        """Build a reporter from parsed CLI args, tolerating missing attributes.

        Honors ``--quiet``/``--verbose`` and ``--format``; falls back to the legacy
        per-command ``--json`` flag when ``--format`` is absent.
        """
        if getattr(args, "quiet", False):
            verbosity = Verbosity.QUIET
        elif getattr(args, "verbose", False):
            verbosity = Verbosity.VERBOSE
        else:
            verbosity = Verbosity.NORMAL
        output_format = getattr(args, "format", None)
        if output_format is None:
            output_format = "json" if getattr(args, "json", False) else "text"
        return cls(verbosity=verbosity, output_format=output_format)

    @property
    def json(self) -> bool:
        return self.output_format == "json"

    def info(self, message: str = "") -> None:
        """Normal status output to stdout (hidden when quiet or in JSON mode)."""
        if self.json or self.verbosity < Verbosity.NORMAL:
            return
        print(message, file=self._stdout)

    def detail(self, message: str = "") -> None:
        """Extra output to stdout, shown only with ``--verbose``."""
        if self.json or self.verbosity < Verbosity.VERBOSE:
            return
        print(message, file=self._stdout)

    def warn(self, message: str) -> None:
        """Warning to stderr; always emitted (stderr never affects stdout JSON)."""
        print(message, file=self._stderr)

    def error(self, message: str) -> None:
        """Error to stderr; always emitted (even when quiet or in JSON mode)."""
        print(message, file=self._stderr)

    def print_result(self, *, text: str, data: object) -> None:
        """Emit a command's primary result to stdout (text, or JSON if requested).

        The result is the point of the command, so it is emitted at every verbosity
        — ``--quiet`` suppresses progress (``info``/``detail``), not the result.
        """
        if self.json:
            print(json.dumps(data, indent=2, sort_keys=True), file=self._stdout)
        else:
            print(text, file=self._stdout)
