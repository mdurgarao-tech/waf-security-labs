# WAF Log Analyzer

A small Python tool that parses a WAF event log (JSON-lines) and prints a triage
summary: blocked vs allowed counts, top triggered rule IDs, top source IPs, most
targeted URIs, attack-type breakdown, and status codes.

This is the kind of first-pass report I build before deciding what is a genuine
attack versus a false positive worth tuning — it turns a wall of log lines into
the few things worth investigating.

## Run it

```bash
python3 waf_log_analyzer.py sample-logs/sample_waf.log
```

Options:
```bash
python3 waf_log_analyzer.py sample-logs/sample_waf.log --top 10   # more rows per section
python3 waf_log_analyzer.py sample-logs/sample_waf.log --json     # machine-readable output
```

## Input format

One JSON object per line:

```json
{"timestamp":"2026-09-11T09:20:00Z","src_ip":"203.0.113.55","uri":"/login","method":"POST","action":"blocked","rule_id":"942100","attack_type":"sqli","status":403}
```

The parser skips malformed lines with a warning rather than crashing — real logs
are messy.

## Sample data

`sample-logs/sample_waf.log` is **synthetic**. All source IPs are from the
RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24),
which are reserved for examples and are not real hosts. No production or client
logs are included.

## How I'd extend it (roadmap)

- Time-bucketing to spot spikes (possible L7 DDoS / scanning bursts).
- Flag source IPs that hit many distinct rule IDs (likely a scanner).
- Separate "high-confidence attack" from "likely false positive" by parameter.
- Export to CSV for a ticket attachment.
