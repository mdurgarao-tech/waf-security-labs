#!/usr/bin/env python3
"""
WAF Log Analyzer
----------------
Parses a WAF audit/event log (JSON-lines format) and produces a summary of
blocked requests: top triggered rule IDs, top source IPs, status-code breakdown,
targeted URIs, and recurring attack categories.

Designed for triage — the kind of first-pass report you build before deciding
what is a real attack versus a false positive worth tuning.

Input format (one JSON object per line), e.g.:
    {"timestamp": "...", "src_ip": "...", "uri": "/login", "method": "POST",
     "action": "blocked", "rule_id": "942100", "attack_type": "sqli",
     "status": 403}

Usage:
    python3 waf_log_analyzer.py sample-logs/sample_waf.log
    python3 waf_log_analyzer.py sample-logs/sample_waf.log --top 10 --json

Only synthetic sample data is included in this repo. No production or client logs.
"""

import argparse
import json
import sys
from collections import Counter


def load_events(path):
    """Yield parsed JSON event dicts from a JSON-lines file, skipping bad lines."""
    events = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
                print(f"  [warn] skipped malformed line {line_no}", file=sys.stderr)
    return events, skipped


def summarize(events, top_n=5):
    """Build a summary dict from the list of WAF events."""
    blocked = [e for e in events if e.get("action", "").lower() == "blocked"]

    summary = {
        "total_events": len(events),
        "blocked": len(blocked),
        "allowed": len(events) - len(blocked),
        "top_rule_ids": Counter(
            e.get("rule_id", "unknown") for e in blocked
        ).most_common(top_n),
        "top_source_ips": Counter(
            e.get("src_ip", "unknown") for e in blocked
        ).most_common(top_n),
        "top_uris": Counter(
            e.get("uri", "unknown") for e in blocked
        ).most_common(top_n),
        "attack_types": Counter(
            e.get("attack_type", "unknown") for e in blocked
        ).most_common(top_n),
        "status_codes": Counter(
            e.get("status", "unknown") for e in blocked
        ).most_common(top_n),
    }
    return summary


def print_report(summary):
    def section(title, rows):
        print(f"\n{title}")
        print("-" * len(title))
        if not rows:
            print("  (none)")
            return
        for key, count in rows:
            print(f"  {count:>5}  {key}")

    print("=" * 44)
    print("WAF LOG ANALYSIS SUMMARY")
    print("=" * 44)
    print(f"Total events : {summary['total_events']}")
    print(f"Blocked      : {summary['blocked']}")
    print(f"Allowed      : {summary['allowed']}")

    section("Top rule IDs (blocked)", summary["top_rule_ids"])
    section("Top source IPs (blocked)", summary["top_source_ips"])
    section("Top targeted URIs (blocked)", summary["top_uris"])
    section("Attack types (blocked)", summary["attack_types"])
    section("Status codes (blocked)", summary["status_codes"])
    print()


def main():
    parser = argparse.ArgumentParser(description="Summarize a WAF JSON-lines log.")
    parser.add_argument("logfile", help="Path to the WAF log (JSON lines).")
    parser.add_argument("--top", type=int, default=5, help="How many top entries per category.")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a report.")
    args = parser.parse_args()

    try:
        events, skipped = load_events(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    if not events:
        print("No valid events found.", file=sys.stderr)
        sys.exit(1)

    summary = summarize(events, top_n=args.top)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_report(summary)
        if skipped:
            print(f"Note: {skipped} malformed line(s) were skipped.\n")


if __name__ == "__main__":
    main()
