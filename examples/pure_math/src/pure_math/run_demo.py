from pure_math.math_ops import count_positive, dot_simple, sum_squares


def main() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    print(f"sum_squares={sum_squares(values)}")
    print(f"dot_simple={dot_simple(values, values)}")
    print(f"count_positive={count_positive([-2, 0, 3, 4])}")


if __name__ == "__main__":
    main()
