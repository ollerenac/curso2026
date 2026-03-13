# Design: fullapt2025 End-to-End Pipeline Plan

**Date**: 2026-03-13
**Type**: Implementation plan design (covers both fullapt2025 + curso2026)
**Spec**: `specs/001-apt-dataset-pipeline/spec.md`

## Context

This design covers the complete roadmap for producing the dual-domain labeled APT dataset
(fullapt2025) and documenting it as a course (curso2026). The plan has 4 phases organized
into a parallel-track structure.

## Decisions Made

| Question | Decision |
|---|---|
| Plan structure | One plan, all 4 phases (not per-phase plans) |
| Phase 3 scope | Extend + fix existing scripts, then run across all 48 runs |
| Phase 2 scope | Comprehensive cross-run analysis (both domains), gated by conclusions doc |
| Phase ordering | Parallel tracks: Phase 1 and Phase 2 run concurrently; Phase 3 gated on both |

## Phase Structure

### Phase 1 — Data Acquisition & Integrity

**Goal**: All 48 runs have both JSONL files verified.

**Status at design time**:
- Runs 01–15: JSONL files present; runs 16–48: not yet downloaded
- Run-06: missing netflow CSV; run-15: missing sysmon CSV

**Tasks**:
1. Download runs 16–48 via SSH — one run at a time to avoid session timeout
2. Integrity check all 48 runs: both JSONL files present, file size > threshold,
   valid JSON (spot-check first/last lines), .gz companion present
3. Produce per-run integrity report (JSON/CSV) as the gate artifact
4. Fix gap CSVs: run-06 netflow, run-15 sysmon

**Gate**: integrity report shows all 48 runs pass both domains.

---

### Phase 2 — Extended Exploratory Analysis

**Goal**: Written conclusions document capturing data quality findings for both domains.

**Runs in parallel with Phase 1** on runs 01–15. Extends to all 48 after Phase 1 completes.

**Tasks**:
1. Create `3c-netflow-crossrun-jsonl-explorer.ipynb` — mirrors notebook 2d for NetFlow JSONL:
   event census across all runs, schema fingerprinting, parse error audit
2. Annotate `2d-sysmon-crossrun-jsonl-explorer.ipynb` with conclusions about Sysmon JSONL
   nuances found across runs (EventID gaps, schema drift, null GUIDs, etc.)
3. Write `exploratory-conclusions.md` capturing:
   - Data quality findings per domain
   - Known anomalies per run
   - Explicit recommendations for Phase 3 pipeline fixes

**Gate**: `exploratory-conclusions.md` committed; all 48 runs analyzed in both notebooks.
This document explicitly gates Phase 3 — no pipeline work begins before it exists.

---

### Phase 3 — Pipeline Execution + Temporal Correlation

**Gate condition**: Phase 1 complete (all 48 JSONL verified) AND Phase 2 gate met.

**Tasks in order**:
1. **Pipeline fixes** — apply targeted fixes to scripts 1–4 informed by Phase 2 conclusions.
   Each fix committed to fullapt2025 before running.
2. **Raw CSV generation** — run pipeline steps 2–3 (JSONL → raw CSV) across all pending
   runs (16–48 + gap runs). Verify output row counts against integrity report.
3. **Sysmon cleaning** — run step 4 across all runs. Document violation categories.
4. **Temporal correlation** — run steps 5–6 across all runs. Produces per-run correlation reports.
5. **Labeling** — run steps 7–10 (seed extraction → lifecycle tracing → labeled Sysmon →
   labeled NetFlow) across all runs using INTEGRATED_netflow_labeler.py.

curso2026 documentation written in parallel for each completed pipeline step, with
`synced with fullapt2025@<hash>` in commit messages (Principle VI).

**Gate**: all 48 runs have labeled Sysmon CSV + labeled NetFlow CSV committed.

---

### Phase 4 — ML Experiments

**Gate condition**: Phase 3 complete.

**Tasks**:
1. **Dataset characterization** — cross-run statistical summary: class balance, feature
   distributions, label coverage per APT campaign.
2. **Baseline experiments** — binary classification (APT vs benign) per domain:
   Sysmon-only, NetFlow-only. Standard classifiers to establish baselines.
3. **Cross-domain experiment** — combined host + network features vs single-domain.
   This demonstrates the novel contribution of the dual-domain dataset.
4. **Results documentation** — one notebook per experiment, reproducible, committed
   with the fullapt2025 hash they depend on.

curso2026 gets a final session documenting experiments and results after Phase 4 completes.

**Gate**: at least one reproducible result per domain (host-only, network-only, combined).

---

## Parallel Track Diagram

```
Phase 1 ─────────────────────────────────────── gate ─┐
         (download 16-48 + integrity all 48)           │
                                                        ▼
Phase 2 ─────────────────────── gate ──────────────► Phase 3 ──── gate ──► Phase 4
         (starts on 01-15,                             (pipeline fixes +     (ML
          finishes after Phase 1)                       run all 48 + label)   experiments)
```

## Commit Cadence

- Every script fix or new notebook → commit to fullapt2025 before documenting in curso2026
- Every curso2026 section → commit includes `synced with fullapt2025@<hash>` (Principle VI)
- Phase gates → marked by a fullapt2025 commit containing the gate artifact

## Plan Location

`specs/001-apt-dataset-pipeline/plan.md` in curso2026, referencing both repos.
