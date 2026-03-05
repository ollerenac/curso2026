# Design: Add ProcessGuid Violation Detection to Notebook 2c

## Problem

The course markdown (`2-analisis-calidad-csv.md`, section 8d) documents ProcessGuid semantic consistency checks and their results, but the actual notebook (`2c-sysmon-csv-exploratory-analysis.ipynb`) does not contain these cells. The notebook is the source of truth — students run it, discover the violations, and the markdown documents those findings.

## Goal

Add GUID→PID and GUID→Image violation detection cells to notebook 2c, run them, and update the markdown to match the actual notebook output.

## Design

### Notebook Changes (2 new cells after cell 24)

**New cell A (markdown):** Section header for semantic consistency checks.

**New cell B (code):** SECTION 9b: PROCESSGUID SEMANTIC CONSISTENCY

The code cell performs:
1. **GUID→PID check**: For each ProcessGuid, verify it maps to exactly 1 ProcessId. Report count of violations.
2. **GUID→Image check**: For each ProcessGuid, verify it maps to exactly 1 Image (case-insensitive, since Windows paths are case-insensitive). Report count of violations.
3. **Violation detail display**: For each violating GUID, show the different Images, PID, event count, and categorize as "false positive" (same binary, different path) vs "genuine collision" (different executables).
4. **Summary statistics**: Total affected events, percentage of dataset.

Coding style matches existing notebook: `if df is not None:` guard, emoji headers, `print()` for output, `display()` for DataFrames.

### Markdown Changes (section 8d update)

After running the notebook cells and obtaining real output, update section 8d in `2-analisis-calidad-csv.md` to match the notebook's actual output format and numbers.

### Files Modified

1. `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/2c-sysmon-csv-exploratory-analysis.ipynb` — insert 2 cells after cell 24
2. `/home/researcher/Research/phd-thesis/curso2026/sesion-2/2-analisis-calidad-csv.md` — update section 8d to match notebook output

### What Does NOT Change

- `3-limpieza-sysmon.md` — already correctly references 8d findings
- Rest of notebook 2c — untouched
- Conclusions section — already accurate
