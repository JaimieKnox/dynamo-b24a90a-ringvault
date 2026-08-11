import sys
from .lab import Lab


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m ringvault CASE_DIR")
    lab = Lab(sys.argv[1])
    raw = sys.stdin.buffer.read()
    sys.stdout.buffer.write(lab.step(raw))


if __name__ == "__main__":
    main()
