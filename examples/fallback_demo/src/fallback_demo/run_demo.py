import os

from fallback_demo.scoring import score_one, score_python_batch


def main() -> None:
    print(f"REXTIO_DISABLE_NATIVE={os.environ.get('REXTIO_DISABLE_NATIVE', '0')}")
    print(f"score_one={score_one(10.0)}")
    print(f"score_python_batch={score_python_batch([1.0, 2.0, 3.0])}")


if __name__ == "__main__":
    main()
