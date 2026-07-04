"""CLI entrypoint packaged into the zipapp."""

import sys

from zipapp_app.core import checksum


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    values = list(range(count))
    print(f"checksum({count} values) = {checksum(values)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
