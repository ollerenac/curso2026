# Design: Constitution v1.1.1 — Tech Stack + Workflow Methodology

**Date**: 2026-03-12
**Type**: Constitution amendment (PATCH — clarifications and additions to existing sections)
**Version bump**: 1.1.0 → 1.1.1

## Context

Three changes batched into one PATCH amendment:

1. **Restore Principle VI** — the on-disk constitution file had Principle VI (Script-First Coherence) manually deleted from the working directory. Git HEAD already has the correct text. This change reconciles disk with HEAD.

2. **Tech Stack: dataset-venv** — all fullapt2025 scripts and notebooks require the project's virtual environment. Adding this as an explicit Tech Stack entry prevents confusion about which Python interpreter to use.

3. **Development Workflow: methodology guidance** — two workflow patterns are common but not yet documented:
   - *Existing code*: assume it is correct, understand what it does, then modify. Principle VI gates apply before documentation.
   - *Greenfield*: when a missing pipeline or exploration step is discovered, write the script first, bring it to a clean state (per Principle VI), then document. Never draft course content for a script that does not yet exist.

## Changes

### Tech Stack (addition)

```markdown
- **Python environment**: `fullapt2025/dataset-venv` — activate before running any
  fullapt2025 script or notebook
```

### Development Workflow (addition after existing steps)

```markdown
**Working with existing fullapt2025 scripts**: The default assumption is that existing
code is correct. Approach by understanding what it does before modifying it. Modify
only to fix actual problems or improve what it already does — then Principle VI gates
apply before documenting.

**Greenfield case**: When a missing pipeline or exploration step is discovered, write
the new script first, bring it to a clean state (per Principle VI), then document it.
Do not draft course content for a script that does not yet exist.
```

### Version line

`1.1.0 → 1.1.1 | LAST_AMENDED_DATE: 2026-03-12`

## Implementation

1. Restore Principle VI text to `.specify/memory/constitution.md` (git checkout from HEAD or manual re-apply)
2. Add `dataset-venv` line to Tech Stack section
3. Add methodology paragraphs to Development Workflow section
4. Bump version to 1.1.1, update amendment date
5. Commit both files
