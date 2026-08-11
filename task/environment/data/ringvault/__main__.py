"""
Minimal CLI driver for RingVault lab.

Usage: python3 -m ringvault CASE_DIR
"""

import sys

from .lab import Lab


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m ringvault CASE_DIR", file=sys.stderr)
        sys.exit(1)
    case_dir = sys.argv[1]
    engine = Lab(case_dir)
    print(f"Loaded case from {case_dir}")
    print(f"  slot={engine.slot} gen={engine.gen} nest_required={engine.nest_required}")
    print(f"  scope={engine.scope} script={engine.script}")
    print("Lab ready. Send framed bytes via Lab.step().")


if __name__ == "__main__":
    main()
