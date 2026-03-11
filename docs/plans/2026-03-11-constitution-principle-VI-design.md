# Design: Constitution Principle VI — Script-First Coherence

**Date**: 2026-03-11
**Type**: Constitution amendment (MINOR — new principle added)
**Version bump**: 1.0.0 → 1.1.0

## Context

curso2026 and fullapt2025 are two separate git repositories representing one
research project. curso2026 is the pedagogical course; fullapt2025 contains the
actual scripts, notebooks, and pipeline that the course documents.

Development flows bidirectionally:
- Developing a course section sometimes reveals problems in fullapt2025 scripts
- Changing a fullapt2025 script sometimes invalidates existing course content

This design documents the agreed principle governing that relationship.

## Decisions Made

| Question | Decision |
|---|---|
| Which project leads? | Scripts lead — fullapt2025 is cleaned up first, then documented |
| How are coordinated changes committed? | curso2026 commit references fullapt2025 hash |
| What happens when fullapt2025 changes independently? | Commit notes stale sections; sections get STALE marker |
| Is there a mandated workflow order? | Yes — scripts must be clean before course documents them |

## Approaches Considered

**A — Script-First Coherence** ✅ Selected
Scripts reach clean state before documentation. Commit traceability enforced
in both directions. Matches the "scripts lead" workflow.

**B — Dual-Repo Synchronization**
Neutral principle focused only on bookkeeping mechanics, no prescribed order.
Rejected: too passive for a solo project where discipline requires explicit rules.

**C — Living Codebase**
Iterative loop framing, course can also drive script fixes.
Rejected: blurs sequencing obligation; the "scripts lead" preference was clear.

## Principle Text (approved)

### VI. Script-First Coherence

A fullapt2025 script or notebook MUST reach a clean, reviewable state before any
curso2026 section documents it. "Clean" means: correct output, no dead code,
canonical file naming, and located in the right directory. A course section MUST
NOT document aspirational or in-progress script behavior — it documents what the
script *actually does*.

**When curso2026 documents a fullapt2025 change:**
The curso2026 commit message MUST reference the fullapt2025 commit hash it depends on:
```
docs: document script X — synced with fullapt2025@<hash>
```

**When fullapt2025 changes independently:**
The fullapt2025 commit message MUST list any affected curso2026 sections. Each
stale section MUST receive a marker at the top:
```html
<!-- STALE: depends on fullapt2025@<hash> — update before next build -->
```
The marker MUST be removed only when the section is updated.

Rationale: If scripts are documented before they are clean, the course teaches bad
practices. If script changes are not tracked, the course silently drifts from the
actual codebase — becoming misleading rather than instructive.

## Implementation

1. Add Principle VI to `.specify/memory/constitution.md`
2. Bump version to 1.1.0, update LAST_AMENDED_DATE to 2026-03-11
3. Commit both files
