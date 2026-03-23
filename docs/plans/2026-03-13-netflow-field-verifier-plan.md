# NetFlow Field Verifier Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Write `2_netflow_field_verifier.py`, a streaming script that scans every record in target NetFlow JSONL files to confirm whether `destination.process.*` fields are genuinely absent.

**Architecture:** Single-pass streaming reader — one line at a time, constant RAM (one str + one set[str] + three ints per run). Writes `dataset/netflow-field-verification.json`. A read-only display cell is added to notebook 3c.

**Tech Stack:** Python 3.10+, stdlib only (`json`, `argparse`, `pathlib`). Venv: `fullapt2025/dataset-venv`.

---

### Task 1: Write the script

**Files:**
- Create: `fullapt2025/scripts/auxiliary/2_netflow_field_verifier.py`

**Step 1: Create the file with this exact content**

```python
#!/usr/bin/env python3
"""
2_netflow_field_verifier.py — Phase 2: Full-scan NetFlow field presence verifier

Streams every record in target NetFlow JSONL files to confirm whether
destination.process.* fields are absent. Uses constant RAM (one line buffer,
one set of field path strings, three counters). No reservoir sampling.

Usage:
    python scripts/auxiliary/2_netflow_field_verifier.py
    python scripts/auxiliary/2_netflow_field_verifier.py --runs 03 09 11 12
    python scripts/auxiliary/2_netflow_field_verifier.py --all
    python scripts/auxiliary/2_netflow_field_verifier.py --dataset /custom/path

Output: dataset/netflow-field-verification.json
"""

import argparse
import json
from pathlib import Path

NETFLOW_PATTERN = "ds-logs-network_traffic-flow-default-*.jsonl"
PROGRESS_INTERVAL = 100_000
DEFAULT_RUNS = ["03", "09", "11", "12"]


def flatten_keys(d: dict, prefix: str = "") -> frozenset:
    """Recursively collect all dotted key paths from a nested dict.

    e.g. {"network": {"transport": "udp"}} -> frozenset({"network", "network.transport"})
    Memory: builds a set of strings; the input dict is not retained.
    """
    keys = set()
    for k, v in d.items():
        full = f"{prefix}.{k}" if prefix else k
        keys.add(full)
        if isinstance(v, dict):
            keys |= flatten_keys(v, full)
    return frozenset(keys)


def scan_run(run_dir: Path, run_id: str) -> dict:
    """Stream the entire NetFlow JSONL for one run, checking every record.

    Memory profile per call:
      - line: str (~2 KB max, immediately replaced each iteration)
      - field_paths: set[str] (grows to ~89 entries, ~3 KB total)
      - total, errors, dp_count: three ints
      - dp_first_line: int or None
    No list of records is ever built.
    """
    jsonl_files = list(run_dir.glob(NETFLOW_PATTERN))
    if not jsonl_files:
        return {
            "run": run_dir.name,
            "error": "No NetFlow JSONL file found",
            "total_records": 0,
            "parse_errors": 0,
            "destination_process_present": None,
            "destination_process_record_count": 0,
            "destination_process_first_line": None,
            "field_count": 0,
            "all_field_paths": [],
        }

    path = jsonl_files[0]
    field_paths: set = set()
    total = 0
    errors = 0
    dp_count = 0
    dp_first_line = None

    size_mb = path.stat().st_size / 1024 / 1024
    print(f"  [{run_id}] Scanning {path.name} ({size_mb:.0f} MB) ...")

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line_num, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                field_paths |= flatten_keys(rec)
                if rec.get("destination", {}).get("process") is not None:
                    dp_count += 1
                    if dp_first_line is None:
                        dp_first_line = line_num
                total += 1
            except (json.JSONDecodeError, ValueError):
                errors += 1
                total += 1

            if total % PROGRESS_INTERVAL == 0:
                print(f"  [{run_id}] {total:,} records processed ...", flush=True)

    dp_present = dp_count > 0
    verdict = "CONFIRMED PRESENT" if dp_present else "CONFIRMED ABSENT"
    detail = (
        f"in {dp_count:,} records (first at line {dp_first_line:,})"
        if dp_present
        else ""
    )
    print(
        f"  [{run_id}] Done. {total:,} records, {errors} errors — "
        f"destination.process: {verdict} {detail}"
    )

    return {
        "run": run_dir.name,
        "total_records": total,
        "parse_errors": errors,
        "destination_process_present": dp_present,
        "destination_process_record_count": dp_count,
        "destination_process_first_line": dp_first_line,
        "field_count": len(field_paths),
        "all_field_paths": sorted(field_paths),
    }


def find_project_root() -> Path:
    """Walk up from this file looking for a directory containing dataset/."""
    current = Path(__file__).resolve().parent
    for _ in range(5):
        if (current / "dataset").is_dir():
            return current
        current = current.parent
    print("ERROR: Could not find project root (no 'dataset/' directory found).")
    raise SystemExit(1)


def discover_run_dirs(dataset: Path, run_ids: list) -> list:
    """Map zero-padded run IDs to their run-XX-apt-Y directories."""
    result = []
    for run_id in run_ids:
        rid = run_id.zfill(2)
        matches = sorted(dataset.glob(f"run-{rid}-apt-*"))
        if not matches:
            print(f"WARNING: No directory found for run {rid}, skipping.")
            continue
        result.append((rid, matches[0]))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2: Full-scan NetFlow field presence verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--runs",
        nargs="+",
        default=DEFAULT_RUNS,
        metavar="RUN_ID",
        help=f"Run IDs to verify (default: {' '.join(DEFAULT_RUNS)})",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Verify all available runs (overrides --runs)",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to dataset directory (default: auto-detected from project root)",
    )
    args = parser.parse_args()

    project_root = find_project_root()
    dataset = args.dataset or project_root / "dataset"

    if not dataset.exists():
        print(f"ERROR: Dataset directory not found: {dataset}")
        raise SystemExit(1)

    if args.all:
        run_ids = [
            d.name.split("-")[1]
            for d in sorted(dataset.glob("run-*-apt-*"))
            if d.is_dir()
        ]
    else:
        run_ids = [r.zfill(2) for r in args.runs]

    run_dirs = discover_run_dirs(dataset, run_ids)
    if not run_dirs:
        print("ERROR: No valid run directories found.")
        raise SystemExit(1)

    print(f"Verifying {len(run_dirs)} run(s): {[r for r, _ in run_dirs]}\n")

    results = []
    for run_id, run_dir in run_dirs:
        result = scan_run(run_dir, run_id)
        results.append(result)
        print()

    output_path = dataset / "netflow-field-verification.json"
    output_path.write_text(json.dumps(results, indent=2))
    print(f"Results written to: {output_path}\n")

    print("=" * 70)
    print(f"{'Run':<25} {'Records':>12} {'Errors':>8}  {'destination.process'}")
    print("-" * 70)
    for r in results:
        if "error" in r:
            print(f"{r['run']:<25} {'N/A':>12} {'N/A':>8}  ERROR: {r['error']}")
            continue
        verdict = (
            "CONFIRMED PRESENT" if r["destination_process_present"] else "CONFIRMED ABSENT"
        )
        detail = (
            f" ({r['destination_process_record_count']:,} records)"
            if r["destination_process_present"]
            else ""
        )
        print(
            f"{r['run']:<25} {r['total_records']:>12,} {r['parse_errors']:>8,}  {verdict}{detail}"
        )
    print("=" * 70)


if __name__ == "__main__":
    raise SystemExit(main())
```

**Step 2: Verify the file exists and is syntactically valid**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate
python -c "import ast; ast.parse(open('scripts/auxiliary/2_netflow_field_verifier.py').read()); print('Syntax OK')"
```

Expected: `Syntax OK`

**Step 3: Check `--help` works**

```bash
python scripts/auxiliary/2_netflow_field_verifier.py --help
```

Expected output includes: `Phase 2: Full-scan NetFlow field presence verifier`

---

### Task 2: Test against run-01 (baseline — destination.process IS present)

Run-01 has 89 field paths in the reservoir sample, so `destination.process.*` should appear in at least some records.

**Step 1: Run against run-01 only**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate
python scripts/auxiliary/2_netflow_field_verifier.py --runs 01
```

**Step 2: Verify expected output**

Expected terminal output (exact numbers will vary):
```
Verifying 1 run(s): ['01']

  [01] Scanning ds-logs-network_traffic-flow-default-run-01.jsonl (1096 MB) ...
  [01] 100,000 records processed ...
  ...
  [01] Done. 569,443 records, 0 errors — destination.process: CONFIRMED PRESENT in X records (first at line Y)

======================================================================
Run                         Records   Errors  destination.process
----------------------------------------------------------------------
run-01-apt-1                569,443        0  CONFIRMED PRESENT (X records)
======================================================================
```

**Step 3: Verify JSON output was written**

```bash
python -c "
import json
r = json.loads(open('dataset/netflow-field-verification.json').read())
assert r[0]['run'] == 'run-01-apt-1'
assert r[0]['destination_process_present'] == True
assert r[0]['destination_process_first_line'] is not None
assert r[0]['field_count'] == 89
print('run-01 assertions PASS')
"
```

Expected: `run-01 assertions PASS`

---

### Task 3: Test against run-03 (expected — destination.process ABSENT)

**Step 1: Run against run-03 only**

```bash
python scripts/auxiliary/2_netflow_field_verifier.py --runs 03
```

**Step 2: Verify expected output**

Expected:
```
  [03] Done. 1,110,996 records, 0 errors — destination.process: CONFIRMED ABSENT

======================================================================
run-03-apt-1              1,110,996        0  CONFIRMED ABSENT
======================================================================
```

**Step 3: Verify JSON output**

```bash
python -c "
import json
r = json.loads(open('dataset/netflow-field-verification.json').read())
run = next(x for x in r if x['run'] == 'run-03-apt-1')
assert run['destination_process_present'] == False
assert run['destination_process_record_count'] == 0
assert run['destination_process_first_line'] is None
assert run['field_count'] == 81
print('run-03 assertions PASS')
"
```

Expected: `run-03 assertions PASS`

---

### Task 4: Run the full default set (runs 03, 09, 11, 12)

This is the definitive verification run. It will take 20–40 minutes total.

**Step 1: Run all four target runs**

```bash
python scripts/auxiliary/2_netflow_field_verifier.py
```

(Default runs: 03, 09, 11, 12)

**Step 2: Verify all four show CONFIRMED ABSENT**

```bash
python -c "
import json
results = json.loads(open('dataset/netflow-field-verification.json').read())
for r in results:
    assert r['destination_process_present'] == False, f\"{r['run']} unexpectedly has destination.process\"
    assert r['parse_errors'] == 0, f\"{r['run']} has parse errors\"
    print(f\"{r['run']}: CONFIRMED ABSENT in {r['total_records']:,} records — PASS\")
print('All assertions PASS')
"
```

Expected:
```
run-03-apt-1: CONFIRMED ABSENT in 1,110,996 records — PASS
run-09-apt-1: CONFIRMED ABSENT in 1,545,775 records — PASS
run-11-apt-1: CONFIRMED ABSENT in 2,641,388 records — PASS
run-12-apt-1: CONFIRMED ABSENT in 1,996,627 records — PASS
All assertions PASS
```

---

### Task 5: Add read-only display cell to notebook 3c

**Files:**
- Modify: `fullapt2025/scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb`

**Step 1: Add new cell at the bottom of the notebook**

Use Python to append the cell to the notebook JSON:

```python
import json

nb_path = "scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb"
with open(nb_path) as f:
    nb = json.load(f)

new_cell_source = '''\
# ── Field verification results (run 2_netflow_field_verifier.py first) ────────
verif_path = PROJECT_ROOT / "dataset" / "netflow-field-verification.json"

if not verif_path.exists():
    print("Field verification results not found.")
    print(f"Run: python scripts/auxiliary/2_netflow_field_verifier.py")
    print("Then re-run this cell.")
else:
    results = json.loads(verif_path.read_text())
    print("=" * 70)
    print("NetFlow destination.process Full-Scan Verification")
    print("=" * 70)
    print(f"{'Run':<25} {'Records':>12} {'Errors':>8}  {'Verdict'}")
    print("-" * 70)
    for r in results:
        verdict = "CONFIRMED PRESENT" if r["destination_process_present"] else "CONFIRMED ABSENT"
        detail = (
            f" ({r['destination_process_record_count']:,} records)"
            if r["destination_process_present"] else ""
        )
        print(f"{r['run']:<25} {r['total_records']:>12,} {r['parse_errors']:>8,}  {verdict}{detail}")
    print("=" * 70)
    print(f"\\nSource: {verif_path}")
'''

new_cell = {
    "cell_type": "code",
    "execution_count": None,
    "id": "cell-verif",
    "metadata": {},
    "outputs": [],
    "source": [line + "\n" for line in new_cell_source.splitlines()],
}
new_cell["source"][-1] = new_cell["source"][-1].rstrip("\n")

nb["cells"].append(new_cell)

with open(nb_path, "w") as f:
    json.dump(nb, f, indent=1)

print("Cell added.")
```

Run this script from the fullapt2025 directory:
```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
python -c "<paste the script above>"
```

**Step 2: Verify the new cell exists**

```bash
python -c "
import json
nb = json.load(open('scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb'))
last = nb['cells'][-1]
assert last['cell_type'] == 'code'
assert 'netflow-field-verification.json' in ''.join(last['source'])
print('Cell present — PASS')
"
```

Expected: `Cell present — PASS`

---

### Task 6: Commit to fullapt2025

**Step 1: Stage both files**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
git add scripts/auxiliary/2_netflow_field_verifier.py
git add scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb
git status
```

Expected: both files shown as staged.

**Step 2: Commit**

```bash
git commit -m "feat(phase2): add 2_netflow_field_verifier — full-scan destination.process audit

Streams every record in target NetFlow JSONL files to confirm whether
destination.process.* fields are genuinely absent (not a reservoir sample).
Writes dataset/netflow-field-verification.json. Adds display cell to 3c.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

**Step 3: Verify commit**

```bash
git log --oneline -3
```

Expected: commit appears at top.
