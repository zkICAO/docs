#!/usr/bin/env python3
"""Checks these documents for the mistakes that have actually happened here.

Two of them, both real. A specification that names a file which does not
exist sends a reader looking for something that is not there, and 127 stale
library paths once reached this repository that way: the layers landed in
the circuits repository and nothing here noticed. A link between two of
these documents that does not resolve is the same failure at a smaller
scale.

The path check needs a checkout of the circuits repository. Pass one as the
first argument. Without it the check says so and skips that part rather than
passing quietly, because a check that reports success when it inspected
nothing is worse than no check at all.

    python3 tools/check.py ../circuits
"""

import re
import sys
from pathlib import Path

# Repository paths are written in backticks, optionally prefixed with the
# repository name.
CODE_PATH = re.compile(r"`(?:circuits/)?((?:lib|bin|tools|fixtures)/[A-Za-z0-9_./]+)`")

# Markdown links to a sibling document.
DOC_LINK = re.compile(r"\[[^\]]*\]\((?!https?:)([A-Za-z0-9_.-]+\.md)(?:#[^)]*)?\)")

# Removed things are described in the past tense on purpose, so a sentence
# that says so is not a broken reference.
REMOVED = re.compile(r"\b(?:was|were|had been) removed\b")

DASHES = {"—": "em dash", "–": "en dash"}


def check(circuits):
    failures = []

    documents = sorted(Path(".").glob("*.md"))

    names = {document.name for document in documents}

    for document in documents:
        for number, line in enumerate(document.read_text().splitlines(), start=1):
            for character, name in DASHES.items():
                if character in line:
                    failures.append(f"{document.name}:{number}: {name}")

            for match in DOC_LINK.finditer(line):
                if match.group(1) not in names:
                    failures.append(
                        f"{document.name}:{number}: links to {match.group(1)}, which is not here"
                    )

            if circuits is None or REMOVED.search(line):
                continue

            for match in CODE_PATH.finditer(line):
                named = match.group(1)

                if not (circuits / named).exists():
                    failures.append(f"{document.name}:{number}: {named} does not exist")

    return failures


def main():
    circuits = None

    if len(sys.argv) > 1:
        candidate = Path(sys.argv[1])

        if not (candidate / "Nargo.toml").exists():
            print(f"no circuits checkout at {candidate}", file=sys.stderr)

            return 2

        circuits = candidate
    else:
        print("no circuits checkout given, so paths into the code are not checked")

    failures = check(circuits)

    for failure in failures:
        print(failure)

    print(f"{len(failures)} problems")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
