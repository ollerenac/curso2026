# NetFlow Field Verifier Design

**Date**: 2026-03-13
**Type**: Implementation design (fullapt2025 auxiliary script)
**Context**: Phase 2 — Extended Exploratory Analysis

## Problem

Notebook 3c identified 4 runs (03, 09, 11, 12) with 81 field paths instead of 89,
apparently missing the entire `destination.process.*` subtree. That finding is based
on a reservoir sample of N=50 records per run — insufficient for 100% confirmation.
Files are 1–2.6 GB each. A definitive, document-by-document scan is needed.

## Solution

A standalone auxiliary script (`2_netflow_field_verifier.py`) that streams each
target run's JSONL file line-by-line, checks every record for `destination.process`
presence, builds a complete field path union, and writes a JSON result file.

## Script Identity

| Property | Value |
|----------|-------|
| File | `fullapt2025/scripts/auxiliary/2_netflow_field_verifier.py` |
| Phase prefix | 2 (Phase 2 — exploratory analysis) |
| Default targets | runs 03, 09, 11, 12 |
| CLI flag | `--runs 03 09 11 12` or `--all` |
| Output | `dataset/netflow-field-verification.json` |

## Memory Model

Only four objects held in RAM per run at any time:

| Object | Type | Max size |
|--------|------|----------|
| Current line buffer | `str` | ~2 KB |
| Field path set | `set[str]` | ~3 KB (≤89 strings) |
| `destination_process_first_line` | `int \| None` | 8 bytes |
| Counters (total, errors, dp_count) | 3× `int` | 24 bytes |

Records are parsed with `json.loads()`, used to update counters and the field set,
then immediately discarded. Files are iterated with `for line in open(path)` —
Python's file iterator uses an 8 KB internal read buffer; no full file is loaded.

Progress is printed to stdout every 100,000 lines.

## Output Format

```json
[
  {
    "run": "run-03-apt-1",
    "total_records": 1110996,
    "parse_errors": 0,
    "destination_process_present": false,
    "destination_process_record_count": 0,
    "destination_process_first_line": null,
    "field_count": 81,
    "all_field_paths": ["destination.ip", "destination.port", "..."]
  }
]
```

## Terminal Summary

```
run-03-apt-1   1,110,996 records   0 errors   destination.process: CONFIRMED ABSENT
run-09-apt-1   1,545,775 records   0 errors   destination.process: CONFIRMED ABSENT
```

Or if unexpectedly present:

```
run-03-apt-1   1,110,996 records   0 errors   destination.process: PRESENT in 145 records (first at line 45,231)
```

## Notebook Integration

One new read-only cell added to the bottom of `3c-netflow-crossrun-jsonl-explorer.ipynb`
that loads `netflow-field-verification.json` and renders the verdict table.
No reprocessing — display only.

## Decisions

| Question | Decision |
|----------|----------|
| Sample vs full scan | Full scan — 100% confirmation required |
| Notebook cell vs script | Standalone script — keeps 3c fast to re-run |
| Extend integrity checker | No — different phase and concern |
| Output location | `dataset/` (alongside `integrity-report.json`) |
