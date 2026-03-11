<!--
  SYNC IMPACT REPORT
  ==================
  Version change: [TEMPLATE] → 1.0.0
  Status: Initial fill from blank template (no prior version)

  Principles defined (new):
    I.   Content-First
    II.  Hybrid Pedagogy
    III. Reproducibility
    IV.  Bilingual Clarity
    V.   Incremental Session Architecture

  Added sections:
    - Core Principles (5 principles)
    - Tech Stack
    - Development Workflow
    - Governance

  Removed sections: N/A (first fill)

  Templates reviewed:
    ✅ .specify/templates/plan-template.md — Constitution Check gates now derivable
       from principles I–V; no structural edit needed (gates are filled per-feature)
    ✅ .specify/templates/spec-template.md — User story format compatible; no change
    ✅ .specify/templates/tasks-template.md — Phase structure compatible; no change
    ✅ .specify/templates/constitution-template.md — source template, read-only

  Deferred TODOs:
    - TODO(RATIFICATION_DATE): exact project inception date unknown; approximate
      2026-01-01 used. Update when confirmed.
-->

# curso2026 Constitution

## Core Principles

### I. Content-First

Every course section MUST have a clear, stated pedagogical purpose before any code or tooling is introduced. Sections exist to teach — not to showcase technology or demonstrate scripts. The instructional goal (what the learner will understand or be able to do) MUST be stated at the top of each section.

Rationale: Without an explicit learning goal, sections drift into reference
documentation or tool tutorials, which undermine the course's applied learning model.

### II. Hybrid Pedagogy

Each substantive section MUST contain all three of the following elements:

- **Conceptual explanation** — prose that explains the *why* before the *how*
- **Annotated code** — fully commented functions with per-line or per-block
  explanations suitable for readers new to the domain
- **Prediction prompt or practical exercise** — an `{admonition}` block that asks the learner to predict an outcome before running code, or a hands-on exercise with a verifiable result

Sections missing any of the three elements MUST be flagged as incomplete. Pure reference appendix sections are exempt from the prediction prompt requirement.

Rationale: Passive reading does not produce learning. The prediction → exploration → reflection loop is the core mechanism of the course's pedagogy.

### III. Reproducibility

All code examples MUST run against the reference fullapt2025 dataset without
modification on any standard installation. The following MUST be enforced:

- Absolute paths are PROHIBITED in committed content; use `Path(__file__).parent` or notebook-relative paths
- Placeholder credentials (SSH host, username, password) MUST use obvious dummy values (e.g., `your-server-ip`, `your-username`) and MUST be clearly annotated
- Dataset file references MUST use the canonical naming patterns defined in the pipeline (e.g., `ds-logs-windows-sysmon_operational-default-run-{run_id}.jsonl`)
- Code cells that require prior pipeline outputs MUST document the prerequisite step at the top of the section

Rationale: A course that cannot be reproduced by the reader is a reference document, not a course.

### IV. Bilingual Clarity

Course content MUST be written in Spanish. The following rules apply:

- Technical proper nouns and standards (EventID, ProcessGuid, NetFlow, CSV, JSONL, APT, Sysmon, IDS) MUST remain in English as they appear in tooling and literature
- On first use of a technical English term, a Spanish gloss or brief parenthetical MUST be provided (e.g., "el ProcessGuid (identificador de proceso)")
- Ambiguous translations that could mislead MUST default to the English term with a Spanish explanation, not a forced translation
- Code identifiers, variable names, and comments inside code blocks MAY be in English to match upstream codebases

Rationale: The target audience reads Spanish but operates tools in English. Forced translations of technical terms create confusion rather than clarity.

### V. Incremental Session Architecture

The six sessions MUST be independently buildable via `jupyter-book build .` from the curso2026 root. The following constraints apply:

- Each session MUST assume only the knowledge covered in prior sessions — no
  forward references to concepts introduced later
- Session notebooks MUST NOT require prior session notebooks to have been executed; all required inputs are either static files or derived from the fullapt2025 pipeline outputs
- Any addition or removal of a section file MUST include a corresponding `_toc.yml` update in the same commit
- Cross-session references MUST use stable relative file paths, not section numbers that may shift
- Each session's `index` file MUST summarize the session's learning goals and list its sections

Rationale: The modular structure enables instructors to assign individual sessions and enables learners to navigate non-linearly without breaking the build.

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

## Tech Stack

- **Build system**: Jupyter Book v1.x (`jupyter-book build .` from curso2026 root)
- **Language**: es (Spanish), configured in `_config.yml → sphinx.config.language`
- **Python**: 3.10+ (matches fullapt2025 pipeline environment)
- **Core libraries**: pandas, matplotlib, seaborn, pathlib, json, xml.etree.ElementTree
- **Notebook format**: `.ipynb` for executable cells; `.md` (MyST) for prose-only sections
- **Repository**: https://github.com/ollerenac/curso2026, branch `main`
- **Dataset dependency**: fullapt2025 at `/home/researcher/Research/phd-thesis/fullapt2025/`
  (referenced but not committed; readers use their own installation)

## Development Workflow

New section additions MUST follow this sequence:

1. Draft prose with stated learning goal (Principle I)
2. Add prediction prompt `{admonition}` before the first exploration cell (Principle II)
3. Write or adapt code with full annotations (Principle II)
4. Add practical exercise or verification step (Principle II)
5. Verify all paths are relative and all credentials are placeholders (Principle III)
6. Update `_toc.yml` if the file is new (Principle V)
7. Run `jupyter-book build .` and confirm zero errors
8. Commit

Session restructuring (reorder, merge, split sessions) MUST include:
- Updated `_toc.yml`
- Audit of all cross-session `{ref}` links
- Update to the session index files affected

## Governance

This constitution MUST supersede all ad-hoc content decisions. When a content
decision conflicts with a principle, the principle prevails unless an amendment
is ratified.

**Amendment procedure**:
1. Describe the proposed change and its rationale in a git commit message or PR
2. Increment `CONSTITUTION_VERSION` per semantic versioning:
   - MAJOR: principle removed or fundamentally redefined
   - MINOR: new principle or section added
   - PATCH: clarification, wording fix, typo
3. Update `LAST_AMENDED_DATE` to the amendment date
4. Re-run `.specify/templates/constitution-template.md` consistency checks

**Compliance**: All session additions and content PRs MUST be reviewed against
Principles I–V. The plan-template's "Constitution Check" section MUST list the
applicable gates from this constitution for each feature.

**Version**: 1.1.0 | **Ratified**: TODO(RATIFICATION_DATE): confirm inception date | **Last Amended**: 2026-03-11
