# Design: Part A Accuracy Rewrite — 5-preprocesamiento.md

**Date**: 2026-03-04
**Scope**: Rewrite Part A (Sysmon JSONL→CSV, Script 2) of `sesion-1/5-preprocesamiento.md` to accurately reflect the actual `2_sysmon_csv_creator.py` implementation
**Approach**: Script-faithful rewrite with same pedagogical scaffolding

## Problem

The current Part A contains multiple critical inaccuracies vs the actual script:

### Critical
1. **fields_per_eventid**: Wrong field lists for EID 1 (17 vs 12 fields), EID 3 (12 vs 16 fields), EID 7 (wrong fields: Signed/Signature vs OriginalFileName/User), EID 10 (wrong fields)
2. **parse_sysmon_event**: Shows `if name and value: fields[name] = value.strip()` but script uses `fields[name] = data.text if data.text else None` (stores None, no strip)
3. **Computer lowercasing**: Script does `.lower()`, markdown doesn't show it

### Significant
4. **EventID 8 GUID case mapping**: Script maps `SourceProcessGuid` → `SourceProcessGUID` (case change). Not mentioned.
5. **sanitize_xml**: Markdown shows regex, script uses character filtering (removes all non-ASCII)
6. **read_jsonl_in_chunks**: Markdown shows `readlines()`, script uses streaming approach
7. Only 8 of 21 EventID schemas shown

### Moderate
8. **clean_dataframe** simplified — missing config flags, empty-string handling, category cardinality check
9. Missing features: backup system, output comparison, auto-detection, bad XML logging, JSON processing logs

## Rewrite Plan

Replace Part A (lines 74-428) with corrected content. Same section structure:

1. **"El desafío: XML dentro de JSON"** — Keep JSON example (illustrative, accurate enough)
2. **"Arquitectura del script"** — Keep ASCII diagram (accurate)
3. **"Lectura y partición en chunks"** — Rewrite to show streaming `for line in f` approach
4. **"Parsing de eventos Sysmon"** — Rewrite both functions to match real implementations
5. **"Esquema por EventID"** — Show ALL 21 EventIDs from actual script. Fix APT relevance table.
6. **"Construcción de registros tabulares"** — Include EventID 8 GUID case mapping
7. **"Procesamiento multi-hilo"** — Minor corrections
8. **"Limpieza y optimización del DataFrame"** — Show real clean_dataframe
9. **"Uso del script"** — Keep (illustrative)

All "Puntos clave" sections will be updated to match corrected code.

## Non-Goals
- No changes to Parts B or C (assessed separately later)
- No changes to exercises (they reference concepts, not specific code)
- No changes to other session files
