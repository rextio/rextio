"""CLI entrypoint compiled by Nuitka into the executable."""

import sys

from nuitka_executable.compute import triangle_mod


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000000
    print(f"triangle_mod({count}) = {triangle_mod(count)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
