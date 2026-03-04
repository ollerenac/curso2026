# Session Restructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split Session 1 into two sessions, add NetFlow exploration/consistency sections, renumber Sessions 2-5 to 3-6.

**Architecture:** Directory cascade rename (reverse order to avoid conflicts), then file moves/renames within sesion-1, then content creation for two new NetFlow files. All index files and cross-references updated. Build verification after each structural change.

**Tech Stack:** Jupyter Book v1.x, Markdown, YAML (`_toc.yml`)

---

### Task 1: Cascade rename session directories (5→6, 4→5, 3→4, 2→3)

Rename in reverse order to avoid conflicts. Git will track these as renames.

**Files:**
- Rename: `sesion-5/` → `sesion-6/`
- Rename: `sesion-4/` → `sesion-5/`
- Rename: `sesion-3/` → `sesion-4/`
- Rename: `sesion-2/` → `sesion-3/`

**Step 1: Rename directories**

```bash
cd /home/researcher/Research/phd-thesis/curso2026
git mv sesion-5 sesion-6
git mv sesion-4 sesion-5
git mv sesion-3 sesion-4
git mv sesion-2 sesion-3
```

**Step 2: Update session numbers in renamed index files**

Modify `sesion-6/index.md`: Change `# Sesión 5:` → `# Sesión 6:` in the heading.

Modify `sesion-5/index.md`: Change `# Sesión 4:` → `# Sesión 5:` in the heading.

Modify `sesion-4/index.md`: Change `# Sesión 3:` → `# Sesión 4:` in the heading.

Modify `sesion-3/index.md`: Change `# Sesión 2:` → `# Sesión 3:` in the heading.

**Step 3: Commit**

```bash
git add -A
git commit -m "Rename session directories: shift sessions 2-5 to 3-6"
```

---

### Task 2: Create new sesion-2 and move preprocessing + quality files

**Files:**
- Create directory: `sesion-2/`
- Move: `sesion-1/5-preprocesamiento.md` → `sesion-2/1-preprocesamiento.md`
- Move: `sesion-1/6-analisis-calidad-csv.md` → `sesion-2/2-analisis-calidad-csv.md`
- Create: `sesion-2/index.md`

**Step 1: Move files**

```bash
cd /home/researcher/Research/phd-thesis/curso2026
mkdir -p sesion-2
git mv sesion-1/5-preprocesamiento.md sesion-2/1-preprocesamiento.md
git mv sesion-1/6-analisis-calidad-csv.md sesion-2/2-analisis-calidad-csv.md
```

**Step 2: Create sesion-2/index.md**

Write this exact content to `sesion-2/index.md`:

```markdown
# Sesión 2: Preprocesamiento y Calidad

**Duración**: 3 horas

## Objetivos

- Transformar datos JSONL en datasets CSV estructurados para ambos dominios
- Aplicar limpieza de calidad sobre el CSV de Sysmon
- Evaluar la calidad del CSV resultante y su readiness para ML

## Contenido

1. [Preprocesamiento: De JSONL a CSV Estructurado](1-preprocesamiento.md) (90 min) — Scripts 2, 3, 4 del pipeline
2. [Análisis de Calidad del CSV](2-analisis-calidad-csv.md) (75 min) — Notebook 2c

## Scripts del Pipeline

Esta sesión cubre los scripts de **preprocesamiento** del pipeline:

| Script | Archivo | Función |
|--------|---------|---------|
| Script 2 | `2_sysmon_csv_creator.py` | Conversión Sysmon JSONL → CSV |
| Script 3 | `3_netflow_csv_creator.py` | Conversión NetFlow JSONL → CSV |
| Script 4 | `4_sysmon_data_cleaner.py` | Limpieza de violaciones ProcessGuid |
```

**Step 3: Commit**

```bash
git add -A
git commit -m "Create sesion-2: move preprocessing and quality from sesion-1"
```

---

### Task 3: Rename sesion-1 files and update index

**Files:**
- Rename: `sesion-1/3-exploracion-datos-crudos.md` → `sesion-1/3-exploracion-sysmon.md`
- Rename: `sesion-1/4-consistencia-estructural.md` → `sesion-1/4-consistencia-sysmon.md`
- Modify: `sesion-1/index.md`

**Step 1: Rename files**

```bash
cd /home/researcher/Research/phd-thesis/curso2026
git mv sesion-1/3-exploracion-datos-crudos.md sesion-1/3-exploracion-sysmon.md
git mv sesion-1/4-consistencia-estructural.md sesion-1/4-consistencia-sysmon.md
```

**Step 2: Rewrite sesion-1/index.md**

Replace the full content of `sesion-1/index.md` with:

```markdown
# Sesión 1: Fundamentos y Exploración de Datos

**Duración**: 5 horas

## Objetivos

- Comprender la arquitectura de recolección de datos dual-domain
- Extraer datos crudos desde Elasticsearch
- Explorar y validar la estructura de los datos JSONL de ambos dominios (Sysmon y NetFlow)
- Comparar las diferencias estructurales entre ambos dominios

## Contenido

1. [Introducción](1-introduccion.md) (45 min)
2. [Extracción de Raw Data](2-extraccion-raw-data.md) (45 min)
3. [Exploración de Datos Sysmon](3-exploracion-sysmon.md) (60 min)
4. [Consistencia Estructural Sysmon](4-consistencia-sysmon.md) (45 min)
5. [Exploración de Datos NetFlow](5-exploracion-netflow.md) (50 min)
6. [Consistencia Estructural NetFlow](6-consistencia-netflow.md) (35 min)
```

**Step 3: Commit**

```bash
git add -A
git commit -m "Rename sesion-1 files: clarify Sysmon scope, update index for 6 sections"
```

---

### Task 4: Update _toc.yml

**Files:**
- Modify: `_toc.yml`

**Step 1: Replace _toc.yml content**

Write this exact content to `_toc.yml`:

```yaml
format: jb-book
root: intro

parts:
  - caption: "Sesión 1: Fundamentos y Exploración de Datos"
    chapters:
      - file: sesion-1/index
        sections:
          - file: sesion-1/1-introduccion
          - file: sesion-1/2-extraccion-raw-data
          - file: sesion-1/3-exploracion-sysmon
          - file: sesion-1/4-consistencia-sysmon
          - file: sesion-1/5-exploracion-netflow
          - file: sesion-1/6-consistencia-netflow

  - caption: "Sesión 2: Preprocesamiento y Calidad"
    chapters:
      - file: sesion-2/index
        sections:
          - file: sesion-2/1-preprocesamiento
          - file: sesion-2/2-analisis-calidad-csv

  - caption: "Sesión 3: Calidad de Datos y Marco Teórico"
    chapters:
      - file: sesion-3/index
        sections:
          - file: sesion-3/1-analisis-calidad
          - file: sesion-3/2-framework-clasificacion
          - file: sesion-3/3-teoria-etiquetado

  - caption: "Sesión 4: Etiquetado Manual Guiado"
    chapters:
      - file: sesion-4/index
        sections:
          - file: sesion-4/1-eventos-semilla
          - file: sesion-4/2-etiquetado-manual
          - file: sesion-4/3-trazado-ciclo-vida

  - caption: "Sesión 5: Generación de Datasets Finales"
    chapters:
      - file: sesion-5/index
        sections:
          - file: sesion-5/1-dataset-eventos-sistema
          - file: sesion-5/2-dataset-trafico-red
          - file: sesion-5/3-validacion-calidad

  - caption: "Sesión 6: Integración y Aplicaciones Avanzadas"
    chapters:
      - file: sesion-6/index
        sections:
          - file: sesion-6/1-workshop-integrador
          - file: sesion-6/2-troubleshooting
          - file: sesion-6/3-aplicaciones-mundo-real
```

**Step 2: Build verification**

```bash
cd /home/researcher/Research/phd-thesis/curso2026
jupyter-book build . 2>&1 | tail -5
```

Expected: Build succeeds (the two new NetFlow files don't exist yet, so there may be warnings, but no fatal errors from the structural changes).

**Step 3: Commit**

```bash
git add _toc.yml
git commit -m "Update _toc.yml for 6-session structure"
```

---

### Task 5: Update cross-references in moved content files

Three files reference "Sesión 2" which is now "Sesión 3":

**Files:**
- Modify: `sesion-2/1-preprocesamiento.md` (was sesion-1/5-preprocesamiento.md)
- Modify: `sesion-2/2-analisis-calidad-csv.md` (was sesion-1/6-analisis-calidad-csv.md)

**Step 1: Fix sesion-2/1-preprocesamiento.md line 742**

Find and replace:
```
en el Script 5 (Sesión 2)
```
With:
```
en el Script 5 (Sesión 3)
```

**Step 2: Fix sesion-2/2-analisis-calidad-csv.md line 253**

Find and replace:
```
habilitando la correlación cruzada en la Sesión 2
```
With:
```
habilitando la correlación cruzada en la Sesión 3
```

**Step 3: Fix sesion-2/2-analisis-calidad-csv.md line 590**

Find and replace:
```
En la **Sesión 2**, usaremos este dataset validado
```
With:
```
En la **Sesión 3**, usaremos este dataset validado
```

**Step 4: Update transition paragraph in sesion-1/4-consistencia-sysmon.md**

The current transition at the end of file 4 points to section 5 (preprocessing). It should now point to section 5 (NetFlow exploration). Find the existing transition paragraph (last paragraph before exercises or at the end of the file) and replace it to say:

```markdown
En la siguiente sección aplicaremos las mismas técnicas de exploración al **dominio NetFlow**, donde descubriremos que la estructura de los datos de tráfico de red presenta características fundamentalmente diferentes al XML embebido de Sysmon.
```

**Step 5: Commit**

```bash
git add -A
git commit -m "Update cross-references for new session numbering"
```

---

### Task 6: Write sesion-1/5-exploracion-netflow.md

**Files:**
- Create: `sesion-1/5-exploracion-netflow.md`

**Reference material:**
- Notebook 3a: `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/3a-exploratory_network-traffic-flow-index.ipynb`
- JSONL file: `/home/researcher/Research/phd-thesis/fullapt2025/dataset/run-01-apt-1/ds-logs-network_traffic-flow-default-run-01.jsonl`

**Content requirements (400-500 lines):**

The file must follow the same pedagogical pattern as `sesion-1/3-exploracion-sysmon.md` but adapted for NetFlow:

1. **Header**: Title "Exploración de Datos NetFlow", Duration 50 min
2. **Context section**: What NetFlow JSONL looks like — pure JSON nesting (no XML), contrast with Sysmon's XML-in-JSON format. Show the dataset path and file size.
3. **Step 1 — Single record inspection**: Show a real record from the JSONL file. Highlight 12 top-level fields (11 always-present + `process`). Show nested dict structure (e.g., `destination.ip`, `source.port`).
4. **Step 2 — Field distribution analysis**: 11 fields always present (100%), `process` at 62.8%. Table of all top-level fields with counts and percentages.
5. **Step 3 — Nested structure deep-dive**: Show how dot-notation paths work (89 total field paths). Group by top-level key. Show depth levels (up to 4).
6. **Step 4 — Data quality**: 1,090,212 total records. Zero nulls for mandatory fields. Contrast with Sysmon's 363,657 records.
7. **Step 5 — Key contrast with Sysmon**: Comparison table:

| Aspecto | Sysmon | NetFlow |
|---------|--------|---------|
| Formato interno | XML en `event.original` | JSON anidado puro |
| Parsing necesario | XML namespace-aware | Navegación de diccionarios |
| Registros (run-01) | 363,657 | 1,090,212 |
| Campos variables | Por EventID (21 esquemas) | Por presencia de `process` |
| Campos nulos | 0% en `EventID`, `Computer` | 0% en 11 campos obligatorios |

8. **Puntos clave** (3-4 bullets)
9. **Actividad Práctica**: 3-4 guided questions
10. **Transition** to section 6 (consistency analysis)

**Accuracy requirement:** All numbers must come from notebook 3a's actual outputs or from reading the actual JSONL file. Reference the notebook with a `{tip}` admonition.

**Step 1: Read notebook 3a to extract exact numbers and code patterns**

Read `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/3a-exploratory_network-traffic-flow-index.ipynb` for:
- Exact field distribution table
- Sample record structure
- Data quality findings
- Code snippets used for exploration

**Step 2: Read a sample record from the actual JSONL file**

```bash
head -1 /home/researcher/Research/phd-thesis/fullapt2025/dataset/run-01-apt-1/ds-logs-network_traffic-flow-default-run-01.jsonl | python3 -m json.tool | head -50
```

**Step 3: Write the file**

Create `sesion-1/5-exploracion-netflow.md` with all content sections listed above.

**Step 4: Build verification**

```bash
jupyter-book build . 2>&1 | tail -5
```

**Step 5: Commit**

```bash
git add sesion-1/5-exploracion-netflow.md
git commit -m "Add sesion-1/5-exploracion-netflow.md: NetFlow JSONL exploration (notebook 3a)"
```

---

### Task 7: Write sesion-1/6-consistencia-netflow.md

**Files:**
- Create: `sesion-1/6-consistencia-netflow.md`

**Reference material:**
- Notebook 3b: `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/3b-structure-consistency-analyzer.ipynb`

**Content requirements (250-300 lines):**

Follows same pattern as `sesion-1/4-consistencia-sysmon.md` but for NetFlow:

1. **Header**: Title "Consistencia Estructural NetFlow", Duration 35 min
2. **Context**: Same fingerprinting technique applied to a different domain. Students already know the method from section 4.
3. **Step 1 — Apply fingerprinting**: Same MD5(sorted field names) technique. Show brief code reminder (or reference section 4).
4. **Step 2 — Results**: **14 structural patterns** found (vs Sysmon's 19 perfectly consistent). Structure diversity ratio: 0.007%. Show pattern distribution table (top 5-10 patterns with counts and percentages).
5. **Step 3 — The `process` field axis**: The primary source of variation. Pattern #1 (33.6%): has `process` + `source.process`. Pattern #2 (33.6%): no `process`. Pattern #3 (27.2%): variant of #1. Explain what this means (process attribution only available for ~64% of flows).
6. **Step 4 — Field co-occurrence**: 89 total field paths. 64 always-present (100%). 17 conditional (mostly `process.*` and `source.process.*`). 8 rare (`destination.process.*` at 2.8%).
7. **Step 5 — Assessment**: "MODERATELY CONSISTENT" vs Sysmon's "HIGHLY CONSISTENT". Explain why: Sysmon has fixed schemas per EventID, NetFlow has variable process attribution.
8. **Implications for Script 3**: The converter must handle the optional `process` field with null defaults. The 64 always-present paths can use simple extraction.
9. **Puntos clave** (3-4 bullets)
10. **Actividad Práctica**: 3-4 guided questions comparing Sysmon and NetFlow consistency
11. **Transition** to Session 2 (preprocessing)

**Accuracy requirement:** All numbers from notebook 3b's actual outputs. Reference the notebook with a `{tip}` admonition.

**Step 1: Read notebook 3b to extract exact numbers**

Read `/home/researcher/Research/phd-thesis/fullapt2025/scripts/exploratory/notebooks/3b-structure-consistency-analyzer.ipynb` for:
- Exact pattern distribution table
- Field co-occurrence numbers
- Consistency assessment text
- Code patterns used

**Step 2: Write the file**

Create `sesion-1/6-consistencia-netflow.md` with all content sections listed above.

**Step 3: Build verification**

```bash
jupyter-book build . 2>&1 | tail -5
```

**Step 4: Commit**

```bash
git add sesion-1/6-consistencia-netflow.md
git commit -m "Add sesion-1/6-consistencia-netflow.md: NetFlow structural consistency (notebook 3b)"
```

---

### Task 8: Final build verification and push

**Step 1: Full build**

```bash
cd /home/researcher/Research/phd-thesis/curso2026
jupyter-book build . 2>&1 | grep -E "(error|warning|finished)"
```

Expected: Build succeeds with no errors. Warnings about missing content in stub files (sesion-3 through sesion-6) are OK.

**Step 2: Verify all files are in place**

```bash
find sesion-1 sesion-2 sesion-3 sesion-4 sesion-5 sesion-6 -name "*.md" | sort
```

Expected: 8 files in sesion-1 (index + 6 content), 3 files in sesion-2 (index + 2 content), 4 files each in sesion-3 through sesion-6.

**Step 3: Push**

```bash
git push
```
