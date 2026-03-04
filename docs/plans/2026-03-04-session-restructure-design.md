# Design: Course Session Restructure — Add NetFlow Sections

**Date**: 2026-03-04
**Scope**: Split Session 1 into two sessions, add NetFlow exploration/consistency sections, renumber Sessions 2-5 to 3-6
**Approach**: Full cascade — all directory renames, file moves, and content creation in one operation

## Problem

Session 1 has a **Sysmon/NetFlow asymmetry**:

| Activity | Sysmon | NetFlow |
|----------|--------|---------|
| Raw JSONL exploration | File 3 (notebook 2a) | NOT COVERED (notebook 3a exists) |
| Structural consistency | File 4 (notebook 2b) | NOT COVERED (notebook 3b exists) |
| JSONL→CSV conversion | File 5 Part A (Script 2) | File 5 Part B (Script 3) |
| CSV quality analysis | File 6 (notebook 2c) | No notebook 3c exists |

Additionally, Session 1 totals ~6h (overflowing the 5h target), and adding NetFlow sections makes this worse.

## Solution

Split Session 1 into two sessions and add dedicated NetFlow sections.

## New Course Structure (6 sessions)

### Session 1: Fundamentos y Exploración de Datos (~4h40)

| # | File | Content | Source | Duration |
|---|------|---------|--------|----------|
| 1 | `1-introduccion.md` | APT context, problem statement | Unchanged | 45 min |
| 2 | `2-extraccion-raw-data.md` | Script 1 walkthrough | Unchanged | 45 min |
| 3 | `3-exploracion-sysmon.md` | Notebook 2a: Sysmon JSONL exploration | Rename from `3-exploracion-datos-crudos.md` | 60 min |
| 4 | `4-consistencia-sysmon.md` | Notebook 2b: Sysmon structural consistency | Rename from `4-consistencia-estructural.md` | 45 min |
| 5 | `5-exploracion-netflow.md` | Notebook 3a: NetFlow JSONL exploration | **NEW** | 50 min |
| 6 | `6-consistencia-netflow.md` | Notebook 3b: NetFlow structural consistency | **NEW** | 35 min |

### Session 2: Preprocesamiento y Calidad (~2h45)

| # | File | Content | Source | Duration |
|---|------|---------|--------|----------|
| 1 | `1-preprocesamiento.md` | Scripts 2, 3, 4 | Move from `sesion-1/5-preprocesamiento.md` | 90 min |
| 2 | `2-analisis-calidad-csv.md` | Notebook 2c: Sysmon CSV quality | Move from `sesion-1/6-analisis-calidad-csv.md` | 75 min |

### Sessions 3-6 (renumbered from old 2-5)

| New # | Old # | Title |
|-------|-------|-------|
| 3 | 2 | Correlación y Marco Teórico (Scripts 5-6, MITRE, labeling theory) |
| 4 | 3 | Etiquetado Manual Guiado (Scripts 7-8) |
| 5 | 4 | Generación de Datasets Finales (Scripts 9-10) |
| 6 | 5 | Integración y Aplicaciones Avanzadas |

## New File Content Plans

### `sesion-1/5-exploracion-netflow.md` (~400-500 lines, based on notebook 3a)

**Pedagogical approach**: Students already learned exploration on Sysmon; NetFlow shows same methodology, different characteristics.

1. **Context**: What NetFlow JSONL looks like — JSON nesting (no XML), contrast with Sysmon
2. **Step 1**: Single record inspection — 12 top-level fields, nested dicts up to depth 4
3. **Step 2**: Field distribution — 11 always-present fields, 1 optional (`process` at 62.8%)
4. **Step 3**: Nested structure deep-dive — 89 field paths, dot-notation navigation
5. **Step 4**: Data quality — 1,090,212 records, zero nulls for mandatory fields
6. **Step 5**: Key contrast with Sysmon (comparison table)
7. Puntos clave, exercise (3-4 questions), transition to section 6

### `sesion-1/6-consistencia-netflow.md` (~250-300 lines, based on notebook 3b)

1. **Context**: Same fingerprinting technique, different results
2. **Step 1**: Apply MD5 fingerprinting to NetFlow
3. **Step 2**: Results — 14 structural patterns (vs Sysmon's 19 perfectly consistent)
4. **Step 3**: The `process` field as primary axis of variation
5. **Step 4**: Field co-occurrence — 64 always-present, 17 conditional, 8 rare
6. **Step 5**: Assessment — "MODERATELY CONSISTENT" vs Sysmon's "HIGHLY CONSISTENT"
7. Implications for Script 3 (how the converter handles variation)
8. Puntos clave, exercise (3-4 questions), transition to Session 2

## File Operations

### Renames (within sesion-1)
- `sesion-1/3-exploracion-datos-crudos.md` → `sesion-1/3-exploracion-sysmon.md`
- `sesion-1/4-consistencia-estructural.md` → `sesion-1/4-consistencia-sysmon.md`

### Moves (sesion-1 → new sesion-2)
- `sesion-1/5-preprocesamiento.md` → `sesion-2/1-preprocesamiento.md`
- `sesion-1/6-analisis-calidad-csv.md` → `sesion-2/2-analisis-calidad-csv.md`

### Directory renames (cascade)
- `sesion-2/` → `sesion-3/` (must happen before the moves above)
- `sesion-3/` → `sesion-4/`
- `sesion-4/` → `sesion-5/`
- `sesion-5/` → `sesion-6/`
- Then create empty `sesion-2/` for the moved files

### Creates
- `sesion-1/5-exploracion-netflow.md` (new content)
- `sesion-1/6-consistencia-netflow.md` (new content)
- `sesion-2/index.md` (new session index)

### Updates
- `_toc.yml` — full restructure (6 sessions instead of 5)
- `sesion-1/index.md` — new 6-section listing
- `sesion-3/index.md` (was sesion-2) — update session number
- `sesion-4/index.md` (was sesion-3) — update session number
- `sesion-5/index.md` (was sesion-4) — update session number
- `sesion-6/index.md` (was sesion-5) — update session number
- Transition paragraphs in `sesion-1/4-consistencia-sysmon.md` (→ section 5 NetFlow)
- Transition paragraph in `sesion-1/6-consistencia-netflow.md` (→ Session 2)
- Internal cross-references in any file mentioning session numbers

## Execution Order

1. **Git renames**: Cascade directories 5→6, 4→5, 3→4, 2→3 (reverse order to avoid conflicts)
2. **Create sesion-2/**: Move preprocessing and quality files in
3. **Rename sesion-1 files**: 3→3-exploracion-sysmon, 4→4-consistencia-sysmon
4. **Update _toc.yml**: Full restructure
5. **Update all index.md files**: Session numbers and section listings
6. **Write new content**: 5-exploracion-netflow.md and 6-consistencia-netflow.md
7. **Update transitions**: Cross-file references and transition paragraphs
8. **Build verification**: `jupyter-book build .`
9. **Commit and push**

## Reference Materials

- Notebook 3a: `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/3a-exploratory_network-traffic-flow-index.ipynb`
- Notebook 3b: `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/3b-structure-consistency-analyzer.ipynb`
- Script 3: `/home/researcher/Research/phd-thesis/fullapt2025/scripts/pipeline/3_netflow_csv_creator.py`

## Non-Goals

- No changes to content within moved files (except transition paragraphs and session references)
- No new NetFlow CSV quality section (no 3c notebook exists)
- No changes to `_config.yml`
