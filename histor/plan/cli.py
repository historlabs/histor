"""`histor plan validate` — validate a plan and print its digest.

Small on purpose. The gate calls :mod:`histor.plan` directly; this exists so a
person can check a plan before proposing it, and so CI can check the example.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from histor.plan import PlanError, annex_xi_gaps, article_5_gaps, load


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("plan", type=Path, nargs="+", help="plan file(s) to validate")
    parser.add_argument("--quiet", action="store_true", help="print nothing on success")
    args = parser.parse_args(argv)

    failed = False
    for path in args.plan:
        try:
            plan = load(path)
        except PlanError as error:
            print(f"{path}: INVALID", file=sys.stderr)
            for problem in error.problems:
                print(f"  - {problem}", file=sys.stderr)
            failed = True
        except (OSError, ValueError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            failed = True
        else:
            if not args.quiet:
                print(f"{path}: ok  sandbox_id={plan.sandbox_id}  plan_digest={plan.digest}")
                if not plan.is_signed:
                    print(f"{path}: note — unsigned; the gate refuses every action under it")
                for gap in article_5_gaps(plan.data):
                    print(f"{path}: note — draft implementing act Art. 5(2){gap}: not declared")
                for gap in annex_xi_gaps(plan.data):
                    print(f"{path}: note — EUSAiR USF Annex XI {gap}: not declared")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
