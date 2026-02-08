#!/usr/bin/env python3
"""Lookup OWASP MASVS controls by keyword, domain, and profile context."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

DATA_FILENAME = "OWASP_MASVS.v2.0.0.json"
BUNDLED_DATA = Path(__file__).resolve().parent.parent / "references" / DATA_FILENAME


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "query",
        nargs="*",
        help="Keyword(s) to match against control ID, statement, description, and domain.",
    )
    parser.add_argument(
        "--domain",
        action="append",
        help="Filter domain(s), e.g., MASVS-NETWORK or NETWORK. Repeatable.",
    )
    parser.add_argument(
        "--level",
        choices=["L1", "L2", "R", "l1", "l2", "r"],
        help="Filter MAS profile context. R maps to MASVS-RESILIENCE controls.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of results to print (default: 20).",
    )
    parser.add_argument(
        "--data",
        type=Path,
        help="Path to MASVS JSON dataset (overrides defaults).",
    )
    parser.add_argument(
        "--show-path",
        action="store_true",
        help="Print resolved data path before results.",
    )
    return parser.parse_args()


def resolve_data_path(cli_path: Path | None) -> Path:
    if cli_path:
        path = cli_path.expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"--data file does not exist: {path}")
        return path

    env_path = os.getenv("MASVS_JSON")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"MASVS_JSON file does not exist: {path}")
        return path

    if BUNDLED_DATA.is_file():
        return BUNDLED_DATA

    raise FileNotFoundError(
        "Unable to find MASVS dataset. Pass --data <path>, set MASVS_JSON, "
        f"or bundle {DATA_FILENAME}."
    )


def load_controls(path: Path) -> tuple[list[dict], dict]:
    payload = json.loads(path.read_text())
    controls = payload.get("controls")
    if not isinstance(controls, list):
        raise ValueError("Invalid MASVS JSON: missing 'controls' list.")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    return controls, metadata


def normalize_domain(value: str) -> str:
    upper = value.upper()
    if upper.startswith("MASVS-"):
        return upper
    return f"MASVS-{upper}"


def matches_domain(control: dict, domain_filters: set[str]) -> bool:
    domain_id = str(control.get("domain_id", "")).upper()
    domain_title = str(control.get("domain_title", "")).lower()
    for needle in domain_filters:
        if needle in domain_id:
            return True
        if needle.lower().replace("masvs-", "") in domain_title:
            return True
    return False


def main() -> int:
    args = parse_args()
    try:
        data_path = resolve_data_path(args.data)
        controls, metadata = load_controls(data_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.show_path:
        print(f"Data: {data_path}")

    level = args.level.upper() if args.level else None
    if level in {"L1", "L2"}:
        print(
            "Note: MASVS v2 dataset does not include per-control L1/L2 mapping; "
            "treating --level as planning context only.",
            file=sys.stderr,
        )

    domain_filters = {normalize_domain(d) for d in (args.domain or [])}
    terms = [t.lower() for t in args.query]

    results = []
    for control in controls:
        domain_id = str(control.get("domain_id", ""))

        if domain_filters and not matches_domain(control, domain_filters):
            continue

        if level == "R" and not (
            domain_id.upper() == "MASVS-RESILIENCE"
            or "MAS-R" in (control.get("profiles_hint") or [])
        ):
            continue

        haystack = " ".join(
            [
                str(control.get("control_id", "")),
                str(control.get("statement", "")),
                str(control.get("description", "")),
                str(control.get("domain_id", "")),
                str(control.get("domain_title", "")),
                " ".join(control.get("profiles_hint") or []),
            ]
        ).lower()

        if terms and not all(term in haystack for term in terms):
            continue

        results.append(control)

    results.sort(key=lambda c: str(c.get("control_id", "")))

    if metadata.get("title"):
        version = metadata.get("version", "unknown")
        print(f"{metadata['title']} ({version})")

    for control in results[: max(args.limit, 0)]:
        hints = control.get("profiles_hint") or []
        hint_suffix = f" | profiles: {','.join(hints)}" if hints else ""
        print(
            f"{control['control_id']} | {control['domain_id']} {control['domain_title']}{hint_suffix}"
        )
        print(f"  {control['statement']}")

    if not results:
        print("No matches found.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
