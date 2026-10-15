"""Prepare a recovery artifact; digest must originate in a trusted release record.

    python -m tools.recover ARCHIVE sha256:DIGEST NEW_DIRECTORY

Fetch and verify signed targets with tools.distribute first. No deployment is changed.
"""
import argparse

from fabric.recovery.artifacts import prepare


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("digest")
    parser.add_argument("destination")
    args = parser.parse_args(argv)
    print(prepare(args.archive, args.digest, args.destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
