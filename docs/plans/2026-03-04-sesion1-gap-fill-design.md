# Design: Session 1 Targeted Gap-Fill

**Date**: 2026-03-04
**Scope**: Improve pedagogical consistency across Session 1 by adding missing elements to files 1, 4, and 6
**Approach**: Targeted Gap-Fill — focus on deficient files, preserve existing good content

## Context

Session 1 has 6 content files. Files 2, 3, 5 follow a strong pedagogical pattern (objectives, context, code, puntos clave, exercises, transitions). Files 1, 4, 6 are missing key elements.

### Current Gap Analysis

| Element            | File 1 | File 2 | File 3 | File 4 | File 5 | File 6 |
|--------------------|--------|--------|--------|--------|--------|--------|
| Puntos clave       | none   | yes    | yes    | partial| yes    | none   |
| Exercises          | 0      | 4      | 4      | 0      | 8      | 0      |
| ASCII diagrams     | images | yes    | yes    | none   | yes    | none   |
| Transition to next | none   | yes    | yes    | none   | yes    | none   |

## Changes Per File

### File 1: `1-introduccion.md`

**Additions (~40-50 lines):**
1. "Puntos clave" after APT case study table (3-4 bullets on why these attacks matter for dataset design)
2. "Puntos clave" after proposed solution (key design decisions: dual-domain, simulated APT, labeled data)
3. Practical exercise: 3 guided reflection questions
   - Which of the 4 limitations is most critical and why?
   - What attack surfaces exist in the infrastructure?
   - Sysmon vs NetFlow sensor coverage for the same attack
4. Transition paragraph to section 2 (data extraction)
5. Verify image paths exist

### File 4: `4-consistencia-estructural.md`

**Additions (~50-60 lines):**
1. ASCII diagram of fingerprinting concept (MD5 of sorted field names)
2. "Puntos clave" after fingerprinting technique (what it reveals, limitations)
3. "Puntos clave" after Step 4 results (1:1 EventID-pattern mapping, field co-occurrence)
4. Practical exercise: 4 questions
   - Why MD5 of sorted field names vs direct comparison?
   - What if two EventIDs shared a fingerprint?
   - 74 fields vs 45 in CSV — what happened?
   - Adapting fingerprinting for NetFlow (no XML)
5. Transition paragraph to section 5 (preprocessing)

### File 6: `6-analisis-calidad-csv.md`

**Additions (~60-70 lines):**
1. "Puntos clave" after Step 4 (temporal analysis significance)
2. "Puntos clave" after Step 8 (design artifacts vs real issues)
3. "Puntos clave" after conclusions (dataset readiness)
4. ASCII diagram of the 10-step quality pipeline
5. Practical exercise: 5 questions
   - Why is 32.1% readiness score misleading?
   - EventID 1 at 36.7% — attack behavior implications
   - TCP 61%, port 444 — security hypothesis
   - ProcessGuid-PID validation test design
   - 5 minimum viable columns for IDS training
6. Transition paragraph to Session 2

## Reference Standard

Cross-reference accuracy against pipeline scripts in `fullapt2025/scripts/pipeline/` (scripts 1-4 only, no notebooks or dataset files).

## Non-Goals

- No changes to files 2, 3, 5 (already well-structured)
- No changes to index.md
- No changes to _toc.yml or _config.yml
- No new files created
- No content rewriting — only additions
