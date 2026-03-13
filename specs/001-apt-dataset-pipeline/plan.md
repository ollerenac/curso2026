# fullapt2025 End-to-End Pipeline — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Produce a fully labeled dual-domain (Sysmon + NetFlow) APT dataset across all 48 runs, documented in curso2026 as a reproducible course.

**Architecture:** Four phases in a parallel-track structure — data acquisition (Phase 1) and extended exploratory analysis (Phase 2) run concurrently; pipeline execution + labeling (Phase 3) is gated on both; ML experiments (Phase 4) follows Phase 3. Every fullapt2025 code change is committed before the corresponding curso2026 section is written.

**Repositories:**
- `fullapt2025`: `/home/researcher/Research/phd-thesis/fullapt2025/`
- `curso2026`: `/home/researcher/Research/phd-thesis/curso2026/`
- Python env: `source /home/researcher/Research/phd-thesis/fullapt2025/dataset-venv/bin/activate`

---

## PHASE 1 — Data Acquisition & Integrity

> Runs **in parallel** with Phase 2. Start Phase 2 immediately on runs 01–15 while Phase 1 downloads the rest.

### Task 1.1: Write integrity check script

**Files:**
- Create: `fullapt2025/scripts/auxiliary/check_run_integrity.py`

**Step 1: Write the script**

```python
#!/usr/bin/env python3
"""
check_run_integrity.py
Verify that every run folder has both JSONL files, non-empty, parseable.
Output: dataset/integrity-report.json
"""
import json, gzip
from pathlib import Path

DATASET = Path(__file__).parent.parent.parent / "dataset"
MIN_BYTES = 1024  # 1 KB minimum

def check_run(run_dir: Path) -> dict:
    run_id = run_dir.name
    result = {"run": run_id, "status": "ok", "issues": []}

    for domain, pattern in [
        ("sysmon", "ds-logs-windows-sysmon_operational-default-*.jsonl"),
        ("netflow", "ds-logs-network_traffic-flow-default-*.jsonl"),
    ]:
        files = list(run_dir.glob(pattern))
        if not files:
            result["issues"].append(f"{domain}: JSONL missing")
            result["status"] = "fail"
            continue
        f = files[0]
        if f.stat().st_size < MIN_BYTES:
            result["issues"].append(f"{domain}: file too small ({f.stat().st_size} bytes)")
            result["status"] = "fail"
            continue
        # Spot-check: read first line
        try:
            with open(f) as fh:
                first = fh.readline()
                json.loads(first)
        except Exception as e:
            result["issues"].append(f"{domain}: first-line parse error: {e}")
            result["status"] = "fail"

    return result

def main():
    runs = sorted(DATASET.glob("run-*-apt-*"))
    report = [check_run(r) for r in runs]
    out = DATASET / "integrity-report.json"
    out.write_text(json.dumps(report, indent=2))
    fails = [r for r in report if r["status"] == "fail"]
    print(f"Checked {len(report)} runs. Failures: {len(fails)}")
    for f in fails:
        print(f"  {f['run']}: {f['issues']}")
    return 1 if fails else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Step 2: Run against runs 01–15 as a smoke test**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate
python scripts/auxiliary/check_run_integrity.py
cat dataset/integrity-report.json | python3 -m json.tool | grep -A3 '"status": "fail"'
```

Expected: runs 01–15 mostly pass; known fails are run-06 (missing netflow CSV is separate) and any integrity issues with the JSONL files themselves.

**Step 3: Commit**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
git add scripts/auxiliary/check_run_integrity.py
git commit -m "feat: add run integrity checker script"
```

---

### Task 1.2: Download runs 16–48 (one at a time)

**Files:**
- Use existing: `fullapt2025/scripts/auxiliary/sysmon_gz_downloader.py`
- Use existing: `fullapt2025/scripts/auxiliary/netflow_gz_downloader.py`

**Background:** The SSH session times out during long transfers. Run one `--run-id` at a time to avoid this.

**Step 1: Download a single run (repeat for each run 16–48)**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate

# Replace XX and Y with actual run and APT numbers
python scripts/auxiliary/sysmon_gz_downloader.py --run-id XX
python scripts/auxiliary/netflow_gz_downloader.py --run-id XX
```

**Step 2: Verify after each download**

```bash
python scripts/auxiliary/check_run_integrity.py
# Check that the newly downloaded run now shows status: ok
```

**Step 3: Commit after each successful run download**

```bash
# Note: JSONL files are not committed to git (too large).
# Commit only if any auxiliary script was modified during the process.
# Log the download progress in a tracking comment or issue.
```

> **Note on run-to-APT mapping:** Use `ls dataset/ | grep run-` to verify which apt number each run belongs to (e.g., runs 19–27 are apt-2).

---

### Task 1.3: Fix gap CSVs

**Known gaps:** run-06 missing netflow CSV, run-15 missing sysmon CSV.

**Step 1: Fix run-06 netflow CSV**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate
python scripts/pipeline/3_netflow_csv_creator.py \
    --input dataset/run-06-apt-1/ds-logs-network_traffic-flow-default-run-06.jsonl \
    --output dataset/run-06-apt-1/03_netflow-run-06.csv
```

**Step 2: Verify output**

```bash
wc -l dataset/run-06-apt-1/03_netflow-run-06.csv
# Must be > 1 (header + at least one row). Should be > 1000 rows.
```

**Step 3: Fix run-15 sysmon CSV**

```bash
python scripts/pipeline/2_sysmon_csv_creator.py \
    --input dataset/run-15-apt-1/ds-logs-windows-sysmon_operational-default-run-15.jsonl \
    --output dataset/run-15-apt-1/02_sysmon-run-15.csv
```

**Step 4: Verify**

```bash
wc -l dataset/run-15-apt-1/02_sysmon-run-15.csv
# Should be > 10000 rows for a standard sysmon run.
```

**Step 5: Run full integrity check**

```bash
python scripts/auxiliary/check_run_integrity.py
# Confirm run-06 and run-15 now show status: ok for JSONL files.
```

---

### Task 1.4: Produce final integrity report (Phase 1 gate)

**Step 1: Run integrity check across all 48 runs**

```bash
python scripts/auxiliary/check_run_integrity.py
# All 48 runs must show status: ok
```

**Step 2: Verify gate condition**

```bash
python3 -c "
import json
r = json.load(open('dataset/integrity-report.json'))
fails = [x for x in r if x['status'] != 'ok']
print(f'Total: {len(r)}, Fails: {len(fails)}')
for f in fails: print(f)
"
# Expected output: Total: 48, Fails: 0
```

**Step 3: Commit gate artifact**

```bash
git add dataset/integrity-report.json
git commit -m "data: integrity-report.json — all 48 runs pass Phase 1 gate"
```

> **PHASE 1 GATE MET** when: `Fails: 0` and integrity-report.json committed.

---

## PHASE 2 — Extended Exploratory Analysis

> Start **immediately** on runs 01–15. Finalize after Phase 1 completes and all 48 runs are available.

### Task 2.1: Create 3c-netflow-crossrun-jsonl-explorer notebook

**Files:**
- Create: `fullapt2025/scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb`
- Reference: `fullapt2025/scripts/exploratory/notebooks/2d-sysmon-crossrun-jsonl-explorer.ipynb`

**Notebook structure** (mirror 2d but for NetFlow JSONL):

**Cell 1 — Header markdown:**
```markdown
# 3c — NetFlow Cross-Run JSONL Explorer
Mirrors notebook 2d for the network domain.
Goal: census, schema fingerprinting, parse error audit across all runs.
```

**Cell 2 — Imports and constants:**
```python
import json, gzip, random
from pathlib import Path
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt

DATASET = Path("../../../../dataset")
RUNS = sorted(DATASET.glob("run-*-apt-*"))
SAMPLE_N = 50  # reservoir sample per run
```

**Cell 3 — Discover runs and JSONL files:**
```python
def discover_netflow_jsonl(runs):
    result = []
    for run in runs:
        files = list(run.glob("ds-logs-network_traffic-flow-default-*.jsonl"))
        if files:
            result.append((run.name, files[0]))
    return result

run_files = discover_netflow_jsonl(RUNS)
print(f"Found NetFlow JSONL in {len(run_files)} runs")
```

**Cell 4 — Two-pass census (event type counts per run):**
```python
def census_pass(jsonl_path):
    type_counts = Counter()
    total = 0
    errors = 0
    with open(jsonl_path) as fh:
        for line in fh:
            try:
                rec = json.loads(line)
                etype = rec.get("_source", {}).get("network", {}).get("type", "unknown")
                type_counts[etype] += 1
                total += 1
            except (json.JSONDecodeError, ValueError):
                errors += 1
    return type_counts, total, errors

census_rows = []
for run_id, path in run_files:
    counts, total, errors = census_pass(path)
    census_rows.append({"run": run_id, "total": total, "errors": errors, **counts})

census_df = pd.DataFrame(census_rows).fillna(0)
census_df
```

**Cell 5 — Event volume bar chart:**
```python
ax = census_df.set_index("run")["total"].plot(kind="bar", figsize=(14, 4))
ax.set_title("NetFlow events per run")
plt.tight_layout()
plt.show()
```

**Cell 6 — Field presence fingerprinting (reservoir sample):**
```python
def reservoir_sample(jsonl_path, n=50):
    sample = []
    for i, line in enumerate(open(jsonl_path)):
        try:
            rec = json.loads(line)
            if len(sample) < n:
                sample.append(rec)
            else:
                j = random.randint(0, i)
                if j < n:
                    sample[j] = rec
        except (json.JSONDecodeError, ValueError):
            pass
    return sample

def field_fingerprint(records):
    def flatten(d, prefix=""):
        keys = set()
        for k, v in d.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.add(full)
            if isinstance(v, dict):
                keys |= flatten(v, full)
        return keys
    return frozenset().union(*[flatten(r) for r in records]) if records else frozenset()

fingerprints = {}
for run_id, path in run_files:
    sample = reservoir_sample(path, SAMPLE_N)
    fingerprints[run_id] = field_fingerprint(sample)
```

**Cell 7 — Schema drift: fields present in some runs but not others:**
```python
all_fields = frozenset().union(*fingerprints.values())
baseline = fingerprints[run_files[0][0]] if run_files else frozenset()

drift_rows = []
for run_id, fp in fingerprints.items():
    missing = baseline - fp
    extra = fp - baseline
    drift_rows.append({"run": run_id, "missing_vs_baseline": len(missing), "extra_vs_baseline": len(extra)})

pd.DataFrame(drift_rows)
```

**Cell 8 — Parse error audit:**
```python
error_rows = census_df[["run", "errors", "total"]].copy()
error_rows["error_rate_%"] = (error_rows["errors"] / error_rows["total"].replace(0, 1) * 100).round(2)
error_rows[error_rows["errors"] > 0]
```

**Cell 9 — Summary markdown:**
```markdown
## Summary
[Fill in after running all cells — document schema consistency, event volume range,
parse error rates, and any runs that look anomalous.]
```

**Step 1: Create the notebook by running all cells on runs 01–15**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate
jupyter nbconvert --to notebook --execute \
    scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb \
    --output scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb
```

**Step 2: Review output, fill in the summary markdown cell manually**

**Step 3: Commit**

```bash
git add scripts/exploratory/notebooks/3c-netflow-crossrun-jsonl-explorer.ipynb
git commit -m "feat: add 3c cross-run NetFlow JSONL explorer notebook"
```

---

### Task 2.2: Annotate 2d with cross-run Sysmon conclusions

**Files:**
- Modify: `fullapt2025/scripts/exploratory/notebooks/2d-sysmon-crossrun-jsonl-explorer.ipynb`

**Step 1: Re-run 2d across all available runs**

```bash
jupyter nbconvert --to notebook --execute \
    scripts/exploratory/notebooks/2d-sysmon-crossrun-jsonl-explorer.ipynb \
    --output scripts/exploratory/notebooks/2d-sysmon-crossrun-jsonl-explorer.ipynb
```

**Step 2: Add a final conclusions cell** (markdown cell at the end of the notebook) documenting:
- EventID coverage: which EventIDs appear in all runs vs only some
- Schema drift: any fields that appear/disappear across runs
- Null GUID prevalence: how many runs have null-GUID events, expected counts
- Parse error rates: any outlier runs
- Recommendations for pipeline step 4 (cleaner)

**Step 3: Commit**

```bash
git add scripts/exploratory/notebooks/2d-sysmon-crossrun-jsonl-explorer.ipynb
git commit -m "docs: annotate 2d with cross-run Sysmon JSONL conclusions"
```

---

### Task 2.3: Write exploratory-conclusions.md (Phase 2 gate artifact)

**Files:**
- Create: `fullapt2025/scripts/exploratory/notebooks/exploratory-conclusions.md`

**Required sections:**

```markdown
# Exploratory Analysis Conclusions

**Date**: YYYY-MM-DD
**Runs analyzed**: XX/48 (update to 48/48 before Phase 3)
**Notebooks**: 2d (Sysmon), 3c (NetFlow)

## Sysmon JSONL Findings

### Schema consistency
[What EventIDs are universal vs run-specific]

### Data quality issues
[Null GUIDs, parse errors, anomalous runs]

### Recommendations for pipeline step 4
[Specific fixes needed in 4_sysmon_data_cleaner.py]

## NetFlow JSONL Findings

### Schema consistency
[Field presence across runs, any drift]

### Data quality issues
[Parse errors, missing fields, anomalous runs]

### Recommendations for pipeline step 3
[Specific fixes needed in 3_netflow_csv_creator.py]

## Cross-domain observations
[Volume correlation between domains per run, runs where one domain is much smaller]

## Phase 3 readiness checklist
- [ ] All 48 runs have JSONL files (see integrity-report.json)
- [ ] No unresolved schema-breaking issues in either domain
- [ ] Pipeline fix list is complete (see recommendations above)
```

**Step 1: Fill the document based on 2d and 3c notebook outputs**

**Step 2: Commit**

```bash
git add scripts/exploratory/notebooks/exploratory-conclusions.md
git commit -m "docs: write exploratory-conclusions.md — Phase 2 gate artifact"
```

> **PHASE 2 GATE MET** when: `exploratory-conclusions.md` committed with all 48 runs analyzed and the Phase 3 readiness checklist fully checked.

---

## PHASE 3 — Pipeline Execution + Temporal Correlation

> **Gate:** Phase 1 gate AND Phase 2 gate must both be met before starting this phase.

### Task 3.1: Apply pipeline fixes from Phase 2 conclusions

**Files:**
- Modify: `fullapt2025/scripts/pipeline/2_sysmon_csv_creator.py` (if needed)
- Modify: `fullapt2025/scripts/pipeline/3_netflow_csv_creator.py` (if needed)
- Modify: `fullapt2025/scripts/pipeline/4_sysmon_data_cleaner.py` (if needed)

**Step 1: Read Phase 2 conclusions recommendations section**

```bash
cat scripts/exploratory/notebooks/exploratory-conclusions.md
```

**Step 2: For each recommended fix, apply, test on run-01, commit**

```bash
# Example: after fixing 2_sysmon_csv_creator.py
python scripts/pipeline/2_sysmon_csv_creator.py \
    --input dataset/run-01-apt-1/ds-logs-windows-sysmon_operational-default-run-01.jsonl \
    --output /tmp/test-sysmon-run-01.csv

# Verify output is non-trivial
wc -l /tmp/test-sysmon-run-01.csv
python3 -c "import pandas as pd; df=pd.read_csv('/tmp/test-sysmon-run-01.csv'); print(df.shape, df.columns.tolist()[:5])"

git add scripts/pipeline/2_sysmon_csv_creator.py
git commit -m "fix: [describe fix] in sysmon csv creator"
```

---

### Task 3.2: Run pipeline steps 2–3 across all pending runs

> Apply to runs that don't yet have valid CSVs (all of 16–48, plus verify 01–15).

**Step 1: Run step 2 (Sysmon JSONL → CSV) for runs missing sysmon CSV**

```bash
cd /home/researcher/Research/phd-thesis/fullapt2025
source dataset-venv/bin/activate

for run_dir in dataset/run-*/; do
    run_id=$(basename "$run_dir" | grep -oP 'run-\K[0-9]+')
    csv="$run_dir/02_sysmon-run-${run_id}.csv"
    jsonl=$(ls "$run_dir"ds-logs-windows-sysmon*.jsonl 2>/dev/null | head -1)
    if [ -n "$jsonl" ] && [ ! -f "$csv" ]; then
        echo "Processing sysmon run-$run_id..."
        python scripts/pipeline/2_sysmon_csv_creator.py --input "$jsonl" --output "$csv"
    fi
done
```

**Step 2: Run step 3 (NetFlow JSONL → CSV) for runs missing netflow CSV**

```bash
for run_dir in dataset/run-*/; do
    run_id=$(basename "$run_dir" | grep -oP 'run-\K[0-9]+')
    csv="$run_dir/03_netflow-run-${run_id}.csv"
    jsonl=$(ls "$run_dir"ds-logs-network_traffic*.jsonl 2>/dev/null | head -1)
    if [ -n "$jsonl" ] && [ ! -f "$csv" ]; then
        echo "Processing netflow run-$run_id..."
        python scripts/pipeline/3_netflow_csv_creator.py --input "$jsonl" --output "$csv"
    fi
done
```

**Step 3: Verify all runs now have both raw CSVs**

```bash
python3 -c "
from pathlib import Path
dataset = Path('dataset')
missing = []
for run in sorted(dataset.glob('run-*-apt-*')):
    rid = run.name.split('-')[1]
    for prefix, name in [('02', 'sysmon'), ('03', 'netflow')]:
        csvs = list(run.glob(f'{prefix}_{name}-run-{rid}.csv'))
        if not csvs:
            missing.append(f'{run.name}: missing {name} csv')
if missing:
    for m in missing: print(m)
else:
    print('All runs have both raw CSVs')
"
```

**Step 4: Commit log files produced by the pipeline**

```bash
git add dataset/run-*/02_log-*.json dataset/run-*/03_log-*.json 2>/dev/null || true
git commit -m "data: pipeline step 2-3 logs for all 48 runs"
```

---

### Task 3.3: Run pipeline step 4 (Sysmon data cleaner) across all runs

**Step 1: Run step 4 for each run that has a sysmon CSV but no cleaned output**

```bash
for run_dir in dataset/run-*/; do
    run_id=$(basename "$run_dir" | grep -oP 'run-\K[0-9]+')
    input_csv="$run_dir/02_sysmon-run-${run_id}.csv"
    violations="$run_dir/04_sysmon-run-${run_id}-violations.csv"
    if [ -f "$input_csv" ] && [ ! -f "$violations" ]; then
        echo "Cleaning sysmon run-$run_id..."
        python scripts/pipeline/4_sysmon_data_cleaner.py \
            --input "$input_csv" \
            --run-id "$run_id"
    fi
done
```

**Step 2: Verify violation reports exist for all runs**

```bash
ls dataset/run-*/04_sysmon-run-*-violations.csv | wc -l
# Expected: 48
```

**Step 3: Commit**

```bash
git add dataset/run-*/04_*.csv
git commit -m "data: pipeline step 4 violation reports for all 48 runs"
```

---

### Task 3.4: Run pipeline steps 5–6 (temporal correlation) across all runs

**Step 1: Run step 5 (enhanced temporal causation correlator)**

```bash
for run_dir in dataset/run-*/; do
    run_id=$(basename "$run_dir" | grep -oP 'run-\K[0-9]+')
    apt_type=$(basename "$run_dir" | grep -oP 'apt-[0-9]+')
    echo "Correlation step 5: run-$run_id ($apt_type)..."
    python scripts/pipeline/5_enhanced_temporal_causation_correlator.py \
        --run-id "$run_id" --apt-type "$apt_type"
done
```

**Step 2: Run step 6 (comprehensive correlation analysis)**

```bash
for run_dir in dataset/run-*/; do
    run_id=$(basename "$run_dir" | grep -oP 'run-\K[0-9]+')
    apt_type=$(basename "$run_dir" | grep -oP 'apt-[0-9]+')
    echo "Correlation step 6: run-$run_id ($apt_type)..."
    python scripts/pipeline/6_comprehensive_correlation_analysis.py \
        --run-id "$run_id" --apt-type "$apt_type"
done
```

**Step 3: Commit correlation outputs**

```bash
git add dataset/run-*/05_* dataset/run-*/06_* 2>/dev/null || true
git commit -m "data: pipeline steps 5-6 correlation outputs for all 48 runs"
```

---

### Task 3.5: Run pipeline steps 7–10 (labeling) across all runs

> Steps 7–9 label the Sysmon domain; step 10 labels the NetFlow domain.
> Step 8 (attack lifecycle tracer) requires manual expert review per run — plan for interactive checkpoints.

**Step 1: Run steps 7–10 using INTEGRATED_netflow_labeler.py**

```bash
for run_dir in dataset/run-*/; do
    run_id=$(basename "$run_dir" | grep -oP 'run-\K[0-9]+')
    apt_type=$(basename "$run_dir" | grep -oP 'apt-[0-9]+')
    echo "Labeling: run-$run_id ($apt_type)..."
    python scripts/exploratory/INTEGRATED_netflow_labeler.py \
        --apt-type "$apt_type" --run-id "$run_id"
    # If interrupted, resume with: --resume --apt-type ... --run-id ...
done
```

**Step 2: Verify labeled CSVs exist for all runs**

```bash
python3 -c "
from pathlib import Path
dataset = Path('dataset')
missing = []
for run in sorted(dataset.glob('run-*-apt-*')):
    labeled = list(run.glob('*labeled*.csv'))
    if not labeled:
        missing.append(run.name)
if missing:
    print('Missing labeled CSVs:')
    for m in missing: print(' ', m)
else:
    print('All 48 runs have labeled CSVs')
"
```

**Step 3: Commit labeled CSVs and logs**

```bash
git add dataset/run-*/07_* dataset/run-*/08_* dataset/run-*/09_* dataset/run-*/10_*
git commit -m "data: labeled dual-domain CSVs for all 48 runs — Phase 3 gate"
```

> **PHASE 3 GATE MET** when: all 48 runs have labeled Sysmon CSV + labeled NetFlow CSV.

---

### Task 3.6: Document pipeline steps in curso2026 (ongoing through Phase 3)

For each pipeline step completed, add a curso2026 section referencing the fullapt2025 commit.

**Commit format (Principle VI):**

```bash
cd /home/researcher/Research/phd-thesis/curso2026
HASH=$(git -C /home/researcher/Research/phd-thesis/fullapt2025 rev-parse --short HEAD)
git commit -m "docs: document pipeline step N — synced with fullapt2025@${HASH}"
```

---

## PHASE 4 — ML Experiments

> **Gate:** Phase 3 gate must be met.

### Task 4.1: Dataset characterization notebook

**Files:**
- Create: `fullapt2025/scripts/exploratory/notebooks/5a-dataset-characterization.ipynb`

**Notebook cells:**

1. Load all labeled Sysmon and NetFlow CSVs across 48 runs
2. Class balance: APT vs benign event counts per run and in aggregate
3. Feature distributions: histograms of key EventIDs (Sysmon) and flow types (NetFlow)
4. Label coverage per APT campaign: what fraction of events are labeled APT
5. Cross-domain volume correlation: Sysmon event count vs NetFlow flow count per run
6. Summary markdown: key statistics for the dataset paper section

**Step 1: Build and run the notebook**

```bash
jupyter nbconvert --to notebook --execute \
    scripts/exploratory/notebooks/5a-dataset-characterization.ipynb \
    --output scripts/exploratory/notebooks/5a-dataset-characterization.ipynb
```

**Step 2: Commit**

```bash
git add scripts/exploratory/notebooks/5a-dataset-characterization.ipynb
git commit -m "feat: add dataset characterization notebook (5a)"
```

---

### Task 4.2: Baseline classification experiments

**Files:**
- Create: `fullapt2025/scripts/exploratory/notebooks/5b-baseline-classification.ipynb`

**Notebook structure:**

1. **Data loading**: load labeled Sysmon CSVs across all runs, split by APT campaign
2. **Feature engineering**: EventID one-hot encoding, process tree depth, time-of-day bins
3. **Sysmon-only baseline**: Random Forest + Gradient Boosting; 5-fold cross-validation; metrics: precision, recall, F1, ROC-AUC
4. **NetFlow-only baseline**: same classifiers on NetFlow features (flow duration, bytes, packets, port numbers)
5. **Results table**: side-by-side comparison of both domain baselines

**Step 1: Build and run**

```bash
jupyter nbconvert --to notebook --execute \
    scripts/exploratory/notebooks/5b-baseline-classification.ipynb \
    --output scripts/exploratory/notebooks/5b-baseline-classification.ipynb
```

**Step 2: Commit**

```bash
git add scripts/exploratory/notebooks/5b-baseline-classification.ipynb
git commit -m "feat: add baseline classification notebook (5b)"
```

---

### Task 4.3: Cross-domain experiment

**Files:**
- Create: `fullapt2025/scripts/exploratory/notebooks/5c-crossdomain-experiment.ipynb`

**Notebook structure:**

1. **Feature fusion**: join Sysmon and NetFlow features by (timestamp window, host)
2. **Combined classifier**: same Random Forest on merged feature set
3. **Comparison**: combined vs Sysmon-only vs NetFlow-only — table and bar chart
4. **Conclusion cell**: does combining domains improve detection? By how much?

**Step 1: Build and run**

```bash
jupyter nbconvert --to notebook --execute \
    scripts/exploratory/notebooks/5c-crossdomain-experiment.ipynb \
    --output scripts/exploratory/notebooks/5c-crossdomain-experiment.ipynb
```

**Step 2: Commit**

```bash
git add scripts/exploratory/notebooks/5c-crossdomain-experiment.ipynb
git commit -m "feat: add cross-domain ML experiment notebook (5c)"
```

> **PHASE 4 GATE MET** when: 5a, 5b, 5c all committed with executed outputs. Results show at least one metric per domain (host-only, network-only, combined).

---

### Task 4.4: Document ML experiments in curso2026

```bash
cd /home/researcher/Research/phd-thesis/curso2026
HASH=$(git -C /home/researcher/Research/phd-thesis/fullapt2025 rev-parse --short HEAD)
git commit -m "docs: add Session 6 — ML experiments — synced with fullapt2025@${HASH}"
```

---

## Phase Gates Summary

| Gate | Condition | Artifact |
|------|-----------|----------|
| Phase 1 | All 48 runs pass integrity check | `dataset/integrity-report.json` |
| Phase 2 | All 48 runs analyzed, conclusions written | `exploratory-conclusions.md` |
| Phase 3 | All 48 runs have labeled dual-domain CSVs | committed labeled CSV files |
| Phase 4 | 5a + 5b + 5c notebooks committed with outputs | notebooks in `exploratory/notebooks/` |

## Commit Convention (Principle VI)

Every curso2026 commit documenting a fullapt2025 script MUST follow:
```
docs: document [step/script] — synced with fullapt2025@<hash>
```

Use this to get the current hash:
```bash
git -C /home/researcher/Research/phd-thesis/fullapt2025 rev-parse --short HEAD
```
