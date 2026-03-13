# Feature Backlog — fullapt2025 Pipeline + curso2026 Course

This document contains the pre-written descriptions for each feature spec to be created.
When you are ready to work on a feature, run:

```
/speckit.specify <paste the description below>
```

Parent plan: `specs/001-apt-dataset-pipeline/plan.md`

---

## Feature 002 — Data Acquisition & Integrity (Phase 1)

**Status**: Ready to specify
**Depends on**: nothing

```
Write a script (check_run_integrity.py) that verifies all 48 run folders in
fullapt2025/dataset/ contain both JSONL files (Sysmon and NetFlow), that each file
is non-empty and parseable, and that a .gz companion exists. The script produces a
per-run integrity report (JSON) as a gate artifact. Also covers downloading the
missing runs 16–48 from the SSH server one run at a time (to avoid session timeout),
and fixing the two known CSV gaps: run-06 is missing its netflow CSV and run-15 is
missing its sysmon CSV. Phase 1 is complete when the integrity report shows all 48
runs passing for both domains.
```

---

## Feature 003 — Extended Exploratory Analysis (Phase 2)

**Status**: Ready to specify (can start on runs 01–15 immediately)
**Depends on**: Feature 002 (for runs 16–48 analysis portion)

```
Extend the cross-run JSONL exploratory analysis to cover both domains. For Sysmon,
annotate the existing notebook 2d-sysmon-crossrun-jsonl-explorer.ipynb with written
conclusions about EventID coverage, schema drift, null GUID prevalence, and parse
error rates across all 48 runs. For NetFlow, create a new notebook
3c-netflow-crossrun-jsonl-explorer.ipynb that mirrors 2d: event census, schema
fingerprinting, and parse error audit across all available runs. Finally, write a
conclusions document (exploratory-conclusions.md) that captures data quality findings
for both domains, known anomalies per run, and explicit recommendations for Phase 3
pipeline fixes. This document is the gate artifact that must exist before the pipeline
execution phase begins.
```

---

## Feature 004 — Sysmon Pipeline Execution (Phase 3 — host domain)

**Status**: Blocked on Feature 002 + Feature 003
**Depends on**: Feature 002 (all 48 JSONL files present), Feature 003 (conclusions doc written)

```
Apply fixes to the Sysmon processing pipeline scripts (steps 2 and 4) informed by
the Phase 2 exploratory conclusions, then execute the full Sysmon processing chain
across all 48 runs: JSONL to raw CSV (step 2), data quality fixing and violation
detection (step 4), seed event extraction (step 7), and attack lifecycle tracing
(step 8). Each script fix must be committed to fullapt2025 before being executed.
Output for each run: a raw sysmon CSV, a violations report, seed events CSV, and
a lifecycle analysis. The gate is all 48 runs having a violation-cleaned sysmon CSV
and a lifecycle analysis output.
```

---

## Feature 005 — NetFlow Pipeline Execution (Phase 3 — network domain)

**Status**: Blocked on Feature 002 + Feature 003
**Depends on**: Feature 002, Feature 003
**Can run in parallel with**: Feature 004

```
Apply fixes to the NetFlow processing pipeline script (step 3) informed by the Phase 2
exploratory conclusions, then execute NetFlow processing across all 48 runs: JSONL to
raw CSV (step 3). Output for each run: a structured NetFlow CSV. The gate is all 48
runs having a valid, non-empty NetFlow CSV with correct column schema.
```

---

## Feature 006 — Temporal Correlation & Dual-Domain Labeling (Phase 3 — correlation)

**Status**: Blocked on Feature 004 + Feature 005
**Depends on**: Feature 004 (Sysmon CSVs), Feature 005 (NetFlow CSVs)

```
Run the dual-domain temporal correlation and labeling pipeline across all 48 runs.
This covers pipeline steps 5 (enhanced temporal causation correlator), 6 (comprehensive
correlation analysis), 9 (create labeled Sysmon dataset), and 10 (create labeled NetFlow
dataset), using the INTEGRATED_netflow_labeler.py for runs that require interactive
expert checkpoints. The gate is all 48 runs having both a labeled Sysmon CSV and a
labeled NetFlow CSV committed to their run folder.
```

---

## Feature 007 — Dataset Characterization & ML Baseline Experiments (Phase 4)

**Status**: Blocked on Feature 006
**Depends on**: Feature 006 (labeled dual-domain CSVs for all 48 runs)

```
Produce three reproducible analysis notebooks demonstrating the value of the
dual-domain labeled dataset. First, a dataset characterization notebook (5a) covering
class balance, feature distributions, and label coverage per APT campaign. Second, a
baseline classification experiment notebook (5b) running binary APT-vs-benign
classifiers on the Sysmon-only and NetFlow-only domains separately, with cross-validation
metrics. Third, a cross-domain experiment notebook (5c) combining host and network
features and showing whether the dual-domain approach improves detection over either
domain alone. Each notebook must be fully executable against the fullapt2025 dataset
without modification.
```

---

## Feature 008 — curso2026 Session Documentation (ongoing, parallel to Phases 1–4)

**Status**: Ongoing — one section per completed pipeline step
**Depends on**: Each corresponding fullapt2025 feature (document after, not before)

```
Build the curso2026 course sections that document each completed fullapt2025 pipeline
step. Each section must follow the Hybrid Pedagogy principle: conceptual explanation
(why before how), fully annotated code, and a prediction prompt before the first
exploration cell. Sections are written after the corresponding fullapt2025 code is
clean and committed (Principle VI). Each curso2026 commit must reference the
fullapt2025 commit hash it was synced with, using the format:
"docs: document [step] — synced with fullapt2025@<hash>".
```

---

## Notes

- Features 004 and 005 can be specified and worked on in parallel once their shared gate (Features 002 + 003) is met.
- Feature 008 is not a one-time spec — it is invoked once per pipeline step as documentation work. Consider creating a sub-spec per session of curso2026 as documentation progresses.
- The speckit branch numbering will auto-increment. The numbers above (002–008) are estimates; the actual number is assigned when you run `/speckit.specify`.
