#!/usr/bin/env python3
"""Command-line access to the learning memory database."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from learning_engine.engine import LearningEngine


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="learning_engine", description="Learning engine CLI")
    parser.add_argument("--db", default=None, help="Override the SQLite database path")
    sub = parser.add_subparsers(dest="command")

    init_parser = sub.add_parser("init", help="Open a new session")
    init_parser.add_argument("--target", required=True)
    init_parser.add_argument("--technologies", default="", help="Comma-separated technology list")
    init_parser.add_argument("--mode", default="hunt", choices=["hunt", "audit", "triage"])
    init_parser.add_argument("--session-id", default=None)
    init_parser.add_argument("--json", action="store_true")

    summary_parser = sub.add_parser("summary", help="Aggregate a session")
    summary_parser.add_argument("--session", required=True)
    summary_parser.add_argument("--json", action="store_true")

    end_parser = sub.add_parser("end", help="Close a session")
    end_parser.add_argument("--session", required=True)
    end_parser.add_argument("--note", default=None)
    end_parser.add_argument("--json", action="store_true")

    findings_parser = sub.add_parser("findings", help="List findings")
    findings_parser.add_argument("--session", default=None)
    findings_parser.add_argument("--target", default=None)
    findings_parser.add_argument("--json", action="store_true")

    sessions_parser = sub.add_parser("sessions", help="List sessions")
    sessions_parser.add_argument("--limit", type=int, default=20)
    sessions_parser.add_argument("--json", action="store_true")

    stats_parser = sub.add_parser("stats", help="Show database statistics")
    stats_parser.add_argument("--json", action="store_true")

    prune_parser = sub.add_parser("prune", help="Remove referentially invalid rows (dry-run by default)")
    prune_parser.add_argument("--orphans", action="store_true", help="Delete rows whose FK target is missing")
    prune_parser.add_argument("--demo", action="store_true", help="Also delete demo rows created by old test-gate runs")
    prune_parser.add_argument("--apply", action="store_true", help="Actually delete (default is a dry run)")
    prune_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    engine = LearningEngine(args.db) if args.db else LearningEngine()

    if args.command == "init":
        technologies = [t.strip() for t in args.technologies.split(",") if t.strip()]
        result = engine.before_recon(
            args.target, technologies, session_id=args.session_id, mode=args.mode
        )
        if args.json:
            print(json.dumps(result, indent=2))
            return 0
        print(f"[+] Session: {result['session_id']}")
        print(f"    Target: {result['target']} | Mode: {result['mode']}")
        print(f"    Past lessons available: {result['past_lessons_count']}")
        return 0

    if args.command == "summary":
        summary = engine.before_summary(args.session)
        if args.json:
            print(json.dumps(summary, indent=2))
            return 0
        if summary["target_package"] is None:
            print(f"[-] Unknown session: {args.session}", file=sys.stderr)
            return 1
        print(f"[*] Session {args.session} — {summary['target_package']}")
        print(f"    Findings: {summary['total_findings']}")
        for severity, count in summary["severity_breakdown"].items():
            if count:
                print(f"      {severity}: {count}")
        print("    Tested surfaces:")
        for row in summary["tested_surfaces"]:
            print(f"      {row['surface']}: {row['count']}x {row['result']}")
        return 0

    if args.command == "end":
        closed = engine.end_session(args.session, args.note)
        if args.json:
            print(json.dumps({"session": args.session, "closed": bool(closed)}, indent=2))
            return 0 if closed else 1
        if closed:
            print(f"[+] Session closed: {args.session}")
            return 0
        print(f"[-] Unknown session: {args.session}", file=sys.stderr)
        return 1

    if args.command == "findings":
        rows = engine.list_findings(args.session, args.target)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        if not rows:
            print("(no findings)")
            return 0
        print(
            f"{'TARGET':<28}{'FINDING ID':<14}{'SEVERITY':<12}{'STATE':<16}"
            f"{'SIG':<10}TITLE"
        )
        for row in rows:
            stored_id = row["finding_id"]
            # Ids are unique per target: "<target>#<finding_id>" when another
            # engagement already owns the plain id.
            short_id = stored_id.split("#", 1)[1] if "#" in stored_id else stored_id
            print(
                f"{row.get('target_package') or '-':<28}{short_id:<14}"
                f"{row['severity']:<12}{row['state']:<16}"
                f"{row['signature_hash']:<10}{row['title']}"
            )
        return 0

    if args.command == "sessions":
        rows = engine.list_sessions(args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        if not rows:
            print("(no sessions)")
            return 0
        print(f"{'SESSION ID':<32}{'TARGET':<30}{'STARTED':<21}ENDED")
        for row in rows:
            print(
                f"{row['session_id']:<32}{row['target_package']:<30}"
                f"{str(row['start_time']):<21}{row['end_time'] or '-'}"
            )
        return 0

    if args.command == "stats":
        print(json.dumps(engine.stats(), indent=2))
        return 0

    if args.command == "prune":
        if not args.orphans and not args.demo:
            print("[-] Nothing selected: pass --orphans and/or --demo", file=sys.stderr)
            return 2
        with engine._connect() as connection:  # noqa: SLF001 - maintenance tool
            orphan_findings = connection.execute(
                "SELECT f.finding_id, f.title FROM findings f "
                "LEFT JOIN sessions s ON f.session_id = s.session_id WHERE s.session_id IS NULL"
            ).fetchall()
            orphan_feedback = connection.execute(
                "SELECT t.id FROM triage_feedback t "
                "LEFT JOIN findings f ON t.finding_id = f.finding_id WHERE f.finding_id IS NULL"
            ).fetchall()
            demo_findings = connection.execute(
                "SELECT finding_id, title FROM findings WHERE title LIKE 'Test Finding%' "
                "OR title LIKE 'DEMO%'"
            ).fetchall()

        targets = []
        if args.orphans:
            targets.append(("orphan findings", [row["finding_id"] for row in orphan_findings]))
            targets.append(("orphan triage_feedback", [row["id"] for row in orphan_feedback]))
        if args.demo:
            targets.append(("demo findings", [row["finding_id"] for row in demo_findings]))

        if args.json:
            print(
                json.dumps(
                    {
                        "dry_run": not args.apply,
                        "targets": [
                            {"label": label, "ids": ids} for label, ids in targets
                        ],
                    },
                    indent=2,
                )
            )
        else:
            for label, ids in targets:
                print(f"[*] {label}: {len(ids)}" + (f" -> {ids}" if ids else ""))
        if not args.apply:
            if not args.json:
                print("[*] Dry run: re-run with --apply to delete these rows")
            return 0

        with engine._connect() as connection:
            for _label, ids in targets:
                for row_id in ids:
                    if isinstance(row_id, int):
                        connection.execute("DELETE FROM triage_feedback WHERE id = ?", (row_id,))
                    else:
                        connection.execute("DELETE FROM findings WHERE finding_id = ?", (row_id,))
        if not args.json:
            print("[+] Pruned")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
