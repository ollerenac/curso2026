---
name: project-context
description: Core facts about the fullapt2025 + curso2026 dual-repo project — read this before generating any spec, plan, or task list.
type: project
---

# Project Context: fullapt2025 + curso2026

## What this project is

A dual-repository research project producing:

1. **fullapt2025** — a dual-domain (host + network) labeled dataset of APT attack events, built from raw Sysmon and NetFlow telemetry exported from an Elasticsearch cluster.
2. **curso2026** — a Spanish-language Jupyter Book course documenting the dataset construction process, enabling learners to understand and reproduce the pipeline.

The two repos are linked: fullapt2025 scripts must be clean and correct before curso2026 documents them (Principle VI — Script-First Coherence).

## Repository locations

| Repo | Path |
|------|------|
| fullapt2025 | `/home/researcher/Research/phd-thesis/fullapt2025/` |
| curso2026 | `/home/researcher/Research/phd-thesis/curso2026/` |
| Python env | `/home/researcher/Research/phd-thesis/fullapt2025/dataset-venv` |

## Dataset structure

- **48 runs** across **6 APT campaigns** (apt-1 through apt-6)
- Run folders: `fullapt2025/dataset/run-XX-apt-Y/` (e.g., `run-01-apt-1`)
- APT campaign mapping:
  - apt-1: runs 01–18
  - apt-2: runs 19–27
  - apt-3: runs 28–35
  - apt-4: runs 36–41
  - apt-5: runs 42–44
  - apt-6: runs 45–48

## Raw data naming conventions

| File | Pattern |
|------|---------|
| Sysmon JSONL | `ds-logs-windows-sysmon_operational-default-run-{XX}.jsonl` |
| NetFlow JSONL | `ds-logs-network_traffic-flow-default-run-{XX}.jsonl` |

## Pipeline outputs (per run)

| Step | Output file pattern | Description |
|------|--------------------|----|
| 2 | `02_sysmon-run-{XX}.csv` | Raw Sysmon CSV |
| 3 | `03_netflow-run-{XX}.csv` | Raw NetFlow CSV |
| 4 | `04_sysmon-run-{XX}-violations.csv` | ProcessGuid violation report |
| 7 | `07_all-target-events-run-{XX}.csv` | Seed events |
| 9 | labeled sysmon CSV | Labeled host-domain dataset |
| 10 | labeled NetFlow CSV | Labeled network-domain dataset |

## Pipeline scripts (fullapt2025/scripts/pipeline/)

| Script | Purpose |
|--------|---------|
| `1_elastic_index_downloader.py` | Download JSONL from Elasticsearch |
| `2_sysmon_csv_creator.py` | Sysmon JSONL → raw CSV |
| `3_netflow_csv_creator.py` | NetFlow JSONL → raw CSV |
| `4_sysmon_data_cleaner.py` | ProcessGuid violation detection + fixing |
| `5_enhanced_temporal_causation_correlator.py` | Dual-domain temporal correlation |
| `6_comprehensive_correlation_analysis.py` | Correlation report generation |
| `7_sysmon_seed_event_extractor.py` | Extract manually-verified APT seed events |
| `8_sysmon_attack_lifecycle_tracer.py` | Trace attack lifecycle (requires expert review) |
| `9_create_labeled_sysmon_dataset.py` | Produce labeled Sysmon CSV |
| `10_create_labeled_netflow_dataset.py` | Produce labeled NetFlow CSV |

## Exploratory notebooks (fullapt2025/scripts/exploratory/notebooks/)

| Notebook | Purpose |
|----------|---------|
| `2a-exploratory_sysmon-index.ipynb` | Sysmon JSONL structure exploration |
| `2b-structure-consistency-analyzer.ipynb` | Sysmon schema consistency |
| `2c-sysmon-csv-exploratory-analysis.ipynb` | Sysmon CSV analysis |
| `2d-sysmon-crossrun-jsonl-explorer.ipynb` | Cross-run Sysmon JSONL census + schema fingerprinting |
| `3a-exploratory_network-traffic-flow-index.ipynb` | NetFlow JSONL structure exploration |
| `3b-structure-consistency-analyzer.ipynb` | NetFlow schema consistency |
| `4a-sysmon-violation-explorer.ipynb` | ProcessGuid violation categorization |

## Current data state (as of 2026-03-13)

- **Runs 01–15**: JSONL files present; most CSVs exist
  - run-06: missing netflow CSV
  - run-15: missing sysmon CSV
- **Runs 16–48**: JSONL files NOT downloaded yet (require SSH session, one run at a time)

## 4-phase implementation plan

| Phase | Goal | Gate artifact |
|-------|------|--------------|
| 1 | All 48 runs have verified JSONL files | `dataset/integrity-report.json` (all 48 pass) |
| 2 | Cross-run exploratory analysis + conclusions | `exploratory-conclusions.md` |
| 3 | Labeled dual-domain CSVs for all 48 runs | labeled CSV files committed |
| 4 | ML classification experiments (baseline + cross-domain) | notebooks 5a, 5b, 5c |

Phases 1 and 2 run in parallel. Phase 3 requires both Phase 1 and Phase 2 gates.

## Speckit feature backlog

See `specs/BACKLOG.md` for pre-written descriptions for features 002–008.
The next feature to implement is **Feature 002** (data acquisition + integrity).

## Commit conventions

- Every fullapt2025 script change → commit to fullapt2025 first
- Every curso2026 section documenting a script → commit includes `synced with fullapt2025@<hash>`
- Stale sections marked with `<!-- STALE: depends on fullapt2025@<hash> -->`

## curso2026 course structure

- 6 sessions, each independently buildable via `jupyter-book build .`
- Language: Spanish (technical English terms preserved + glossed on first use)
- Each section: conceptual explanation + annotated code + prediction prompt
- Build command: `jupyter-book build .` from `curso2026/` root
