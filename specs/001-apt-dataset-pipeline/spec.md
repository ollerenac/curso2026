# Feature Specification: Dual-Domain APT Dataset Pipeline and Course

**Feature Branch**: `001-apt-dataset-pipeline`
**Created**: 2026-03-13
**Status**: Draft

## Overview

This is the foundational project spec for the two linked repositories:

- **fullapt2025** — builds a dual-domain (host + network) labeled dataset of APT events from raw Sysmon and NetFlow JSONL files, producing labeled CSV datasets suitable for IDS/ML research.
- **curso2026** — a structured course that teaches the concepts, methods, and pipeline steps used to build the dataset, enabling learners to understand and reproduce the entire process.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Reproduce the Dataset End-to-End (Priority: P1)

A researcher with access to the raw JSONL files (Sysmon + NetFlow) wants to reproduce the complete labeled CSV dataset by following the documented pipeline steps.

**Why this priority**: The dataset is the primary artifact of the project. Every downstream use (research, teaching, publication) depends on it being reproducible.

**Independent Test**: A researcher with no prior context can follow the pipeline documentation and produce CSV files matching the expected row counts and label distributions for at least one run (e.g., run-01-apt-1).

**Acceptance Scenarios**:

1. **Given** raw Sysmon JSONL files for a run, **When** the pipeline scripts are executed in documented order, **Then** a labeled CSV file is produced with correct EventID distribution and no data loss beyond documented exclusion rules.
2. **Given** raw NetFlow JSONL files for a run, **When** the pipeline scripts are executed in documented order, **Then** a labeled CSV file is produced with correct flow records and APT-labeled entries.
3. **Given** both CSV files (Sysmon + NetFlow) for a run, **When** the labeling step is applied, **Then** APT-activity events are correctly distinguished from benign background events.

---

### User Story 2 — Follow the Course to Understand the Pipeline (Priority: P2)

A learner (graduate student or security researcher) wants to follow curso2026 session by session and understand both the conceptual foundations (APT, IDS, Sysmon, NetFlow) and the practical processing steps.

**Why this priority**: The course is the pedagogical deliverable. Without it, the pipeline is undocumented code; with it, the project becomes a teachable, transferable contribution.

**Independent Test**: A learner with background knowledge in cybersecurity (but no prior exposure to the project) can complete Session 1 independently and pass its self-assessment exercises with no external help.

**Acceptance Scenarios**:

1. **Given** a learner opens curso2026, **When** they read Session 1, **Then** they can explain what APT is, why dual-domain data matters, and what the pipeline does at a high level.
2. **Given** a learner reaches a session covering a pipeline script, **When** they follow the prediction → exploration → reflection sequence, **Then** they can predict and verify the output of each pipeline step.
3. **Given** a learner completes all 6 sessions, **When** they are given a new raw JSONL run, **Then** they can identify which pipeline step applies and execute it correctly.

---

### User Story 3 — Explore Dataset Characteristics (Priority: P3)

A researcher wants to use the exploratory notebooks and scripts to understand the statistical properties of the dataset (event distributions, schema consistency, coverage per run) before applying it to ML or IDS experiments.

**Why this priority**: Exploratory analysis is a prerequisite for trust. Researchers need to verify the dataset before citing or using it.

**Independent Test**: A researcher can open an exploratory notebook, run all cells against the fullapt2025 reference run, and get summary statistics with no manual intervention.

**Acceptance Scenarios**:

1. **Given** the labeled CSV dataset, **When** an exploratory notebook is executed, **Then** it produces EventID frequency distributions, per-run coverage summaries, and schema consistency reports.
2. **Given** a dataset with known violations (e.g., null ProcessGuids), **When** the violation explorer notebook is run, **Then** violations are categorized and a recommendation is provided for each category.

---

### Edge Cases

- What happens when a raw JSONL file is missing or corrupted for one run? The pipeline must log the failure and skip that run without affecting other runs.
- What happens when an APT campaign produces no NetFlow entries for a run? The dataset for that run must be marked as host-only and documented.
- What happens when a new Sysmon version introduces new EventIDs not present in prior runs? The schema fingerprint comparison step must flag the new IDs for review.
- What happens when a learner has a different OS or Python environment? All course code must run on any standard installation with the documented environment (dataset-venv).

---

## Requirements *(mandatory)*

### Functional Requirements

**Pipeline (fullapt2025)**

- **FR-001**: The pipeline MUST convert raw Sysmon JSONL files into labeled CSV files with one row per event and a label column distinguishing APT from benign activity.
- **FR-002**: The pipeline MUST convert raw NetFlow JSONL files into labeled CSV files with one row per flow record and equivalent labeling.
- **FR-003**: The pipeline MUST produce a processing log for each run documenting: input file size, event counts, parse errors, and output row count.
- **FR-004**: The pipeline MUST be executable run-by-run so that a failure in one run does not prevent processing of others.
- **FR-005**: All pipeline scripts MUST produce identical output when re-run against the same input (deterministic, no timestamps or random seeds in output).
- **FR-006**: The pipeline MUST document any events excluded from the CSV output and the reason for exclusion.

**Course (curso2026)**

- **FR-007**: The course MUST cover all pipeline steps from raw JSONL ingestion through final labeled CSV output, in the order a new practitioner would encounter them.
- **FR-008**: Each course session MUST be independently readable and buildable without requiring other sessions to have been executed first.
- **FR-009**: Every code example in the course MUST run against the fullapt2025 reference dataset without modification.
- **FR-010**: The course MUST include at least one prediction exercise per section asking the learner to anticipate output before executing code.
- **FR-011**: The course MUST be written in Spanish, with English technical terms preserved and glossed on first use.

### Key Entities

- **Run**: A single data collection session, identified by `run-id` (e.g., run-01) and APT campaign (e.g., apt-1). Contains one Sysmon JSONL and one NetFlow JSONL.
- **Event**: A single Sysmon or NetFlow record, with a unique EventID (Sysmon) or flow tuple (NetFlow), a timestamp, and a host identifier.
- **Label**: A binary or categorical annotation on an event indicating whether it is part of an APT activity or benign background traffic.
- **Pipeline Step**: A single script or notebook that takes a specific input (JSONL or CSV) and produces a specific output (CSV or report), with a documented purpose and log.
- **Course Session**: One of the six independently-buildable units of curso2026, each covering a defined set of pipeline steps and domain concepts.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All 48 runs (6 APT campaigns × 8 runs each) produce complete labeled CSV files for both Sysmon and NetFlow domains with zero silent failures (all failures logged and explained).
- **SC-002**: A new practitioner can reproduce the labeled dataset for at least one run within one working day by following only the documented pipeline steps.
- **SC-003**: All 6 curso2026 sessions build without errors using `jupyter-book build .` from the repository root.
- **SC-004**: At least 90% of course code cells execute without error against the reference fullapt2025 dataset on a clean environment with dataset-venv activated.
- **SC-005**: Every pipeline script is documented in at least one course section before the corresponding run data is published or shared.
- **SC-006**: Schema consistency holds across all runs: any EventID present in more than 50% of runs is covered by at least one course section.

---

## Assumptions

- The reference dataset is fullapt2025 at `/home/researcher/Research/phd-thesis/fullapt2025/` with 48 runs across 6 APT campaigns.
- "Labeled" means: each event row has a column indicating whether it falls within the time window of a known APT activity phase.
- The course audience has background in cybersecurity concepts (knows what APT, IDS, and packet capture mean) but has not used Sysmon or NetFlow specifically.
- Runs 16–48 depend on a fresh SSH session to download and convert; this is a known pending task, not a spec requirement.
- The virtual environment for all scripts is `fullapt2025/dataset-venv`.
