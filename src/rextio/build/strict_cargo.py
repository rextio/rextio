"""Pure helper for fail-closed Cargo command construction in strict mode."""

from __future__ import annotations

from collections.abc import Sequence


STRICT_CARGO_FLAGS: tuple[str, ...] = ("--locked", "--offline", "--frozen")
_MAX_CARGO_ARGV = 256
_MAX_CARGO_ARG_CHARS = 4096


class StrictCargoCommandError(ValueError):
    """A Cargo command cannot be made strict without ambiguity."""


def enforce_strict_cargo_command(
    command: Sequence[str],
    *,
    strict: bool,
) -> tuple[str, ...]:
    """Return ``command`` with one canonical strict-flag set before ``--``.

    Non-strict commands are only normalized to an immutable tuple. Strict mode
    rejects value-style lookalikes instead of guessing whether Cargo would
    interpret them as enabling or disabling a required safety property.
    """
    argv = tuple(command)
    if not all(type(item) is str for item in argv):
        raise StrictCargoCommandError("Cargo command arguments must be strings")
    if len(argv) > _MAX_CARGO_ARGV or any(
        not item or len(item) > _MAX_CARGO_ARG_CHARS or "\0" in item for item in argv
    ):
        raise StrictCargoCommandError("Cargo command arguments are outside the allowed bounds")
    if not strict:
        return argv
    if len(argv) < 2:
        raise StrictCargoCommandError("strict Cargo command requires a program and subcommand")
    for item in argv:
        if any(item.startswith(f"{flag}=") for flag in STRICT_CARGO_FLAGS):
            raise StrictCargoCommandError("strict Cargo flag value override is forbidden")

    separator = argv.index("--") if "--" in argv else len(argv)
    cargo_args = [item for item in argv[:separator] if item not in STRICT_CARGO_FLAGS]
    trailing = argv[separator:]
    return (*cargo_args, *STRICT_CARGO_FLAGS, *trailing)


__all__ = [
    "STRICT_CARGO_FLAGS",
    "StrictCargoCommandError",
    "enforce_strict_cargo_command",
]
