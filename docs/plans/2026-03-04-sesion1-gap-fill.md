# Session 1 Pedagogical Gap-Fill Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add missing pedagogical elements (Puntos clave, exercises, diagrams, transitions) to 3 files in Session 1 to match the quality standard of the other 3 files.

**Architecture:** Pure content additions via Edit tool — no file creation, no structural changes. Each task modifies one file by appending/inserting content blocks at specific line locations. Content is in Spanish, matching the existing course style.

**Tech Stack:** Jupyter Book v1.x (Sphinx-based), Markdown with MyST directives, `jupyter-book build .` for verification.

---

### Task 1: Add pedagogical elements to `1-introduccion.md`

**Files:**
- Modify: `sesion-1/1-introduccion.md` (currently 82 lines)

**Step 1: Add "Puntos clave" after APT case study table (after line 24)**

Insert after the APT attacks table (after `| 2021  | Iranian Railway...`):

```markdown

**Puntos clave:**
- Los ataques APT reales a sistemas ciberfísicos demuestran que las amenazas son **multi-etapa** y **multi-dominio**: afectan tanto la red como los procesos del sistema operativo simultáneamente.
- La mayoría de estos ataques fueron detectados *después* de causar daño, lo que subraya la necesidad de sistemas IDS más avanzados.
- Para entrenar IDS efectivos, necesitamos datasets que capturen esta complejidad dual (host + red), no solo un tipo de telemetría.
```

**Step 2: Add "Puntos clave" after proposed solution (after line 81, end of bridge mode explanation)**

Insert at the end of the file:

```markdown

**Puntos clave:**
- La solución propuesta aborda las 4 limitaciones identificadas: (1) datos dual-domain (Sysmon + NetFlow), (2) ataques APT multi-etapa reales, (3) un pipeline de etiquetado estructurado, y (4) un dataset propio sin restricciones de divulgación.
- La infraestructura virtual permite repetir experimentos con diferentes campañas APT de forma controlada y reproducible.
- Los sensores Sysmon capturan actividad a nivel de proceso (creación, acceso a archivos, registro), mientras que NetFlow captura flujos de tráfico de red — juntos proporcionan visibilidad completa.
```

**Step 3: Add practical exercise section (append to end of file)**

Append:

```markdown

## Actividad Práctica

### Ejercicio: Reflexión sobre el Diseño del Dataset

Responde las siguientes preguntas basándote en el contexto presentado:

1. **De las 4 limitaciones identificadas en los datasets existentes**, ¿cuál consideras la más crítica para la investigación en IDS y por qué? Piensa en cómo cada limitación afecta la capacidad de entrenar modelos de detección.

2. **Observando la tabla de infraestructura virtual**, identifica al menos 3 superficies de ataque que un adversario podría explotar. Considera: servicios expuestos, comunicación entre subredes, y puntos de recolección de datos.

3. **Si un atacante ejecuta un script malicioso en un cliente Windows 10 (ITM4) que se conecta a un servidor C2 externo**, ¿qué información capturaría un sensor Sysmon vs un sensor NetFlow? ¿Qué información solo estaría disponible combinando ambos dominios?

### Resultado esperado

Al finalizar esta sección, deberías comprender:
- La motivación detrás de la creación de un dataset dual-domain propio.
- Las limitaciones de los datasets existentes que este proyecto busca superar.
- La arquitectura de red virtual donde se ejecutan las campañas APT.
- Por qué la combinación de Sysmon y NetFlow proporciona una visión más completa que cualquier dominio por separado.

En la siguiente sección, veremos cómo **extraer los datos crudos** desde el clúster Elasticsearch donde se almacenan las dos fuentes de telemetría.
```

**Step 4: Build and verify**

Run: `cd /home/researcher/Research/phd-thesis/curso2026 && jupyter-book build .`
Expected: Build succeeds, no errors related to `1-introduccion.md`

**Step 5: Commit**

```bash
git add sesion-1/1-introduccion.md
git commit -m "Add puntos clave, exercises, and transition to 1-introduccion.md"
```

---

### Task 2: Add pedagogical elements to `4-consistencia-estructural.md`

**Files:**
- Modify: `sesion-1/4-consistencia-estructural.md` (currently 293 lines)

**Step 1: Add ASCII diagram and "Puntos clave" after fingerprinting technique (after line 46)**

Insert after the fingerprint example paragraph (`...generarán el mismo hash.`):

```markdown

```
Concepto del Fingerprinting Estructural:

  Registro XML (EventID 12)        Fingerprint
  ┌─────────────────────────┐
  │ EventType: CreateKey    │      1. Extraer nombres de campo
  │ Image: C:\...\lsass.exe │  ──► [EventType, Image, ProcessGuid,
  │ ProcessGuid: {3fc4...}  │      ProcessId, RuleName, TargetObject,
  │ ProcessId: 648          │      User, UtcTime]
  │ RuleName: -             │
  │ TargetObject: HKLM\... │      2. Ordenar alfabéticamente
  │ User: NT AUTHORITY\...  │  ──► "12|EventType:present|Image:present|..."
  │ UtcTime: 2025-03-19...  │
  └─────────────────────────┘      3. Hash MD5
                                ──► "a7b3c9d1e2f4..."
```

**Puntos clave:**
- El fingerprinting reduce un problema de comparación O(n²) a uno O(n): en lugar de comparar cada par de registros, se genera un hash por registro y se agrupan los iguales.
- La inclusión del EventID en el hash garantiza que eventos de tipos diferentes nunca compartan fingerprint, incluso si tuvieran los mismos campos.
- Se distingue entre campo **presente** y campo **null** — esto detectaría EventIDs con campos opcionales (que en nuestro dataset no existen, pero es una precaución de diseño).
```

**Step 2: Add "Puntos clave" after Step 4 results (after line 266, after "EVALUACIÓN GENERAL: ALTAMENTE CONSISTENTE")**

Insert after the consistency report code block:

```markdown

**Puntos clave:**
- La correspondencia perfecta 1:1 entre patrones y EventIDs confirma que **no existen variaciones internas** — cada EventID siempre produce exactamente los mismos campos. Esto simplifica enormemente el diseño del conversor CSV.
- EID 17 y EID 18 comparten la misma estructura de campos pero son diferenciados por el fingerprint gracias a la inclusión del EventID en el hash. Sin esta precaución, aparecerían como un solo patrón.
- Los 2 campos universales (`UtcTime`, `RuleName`) serán las columnas presentes en **todas las filas** del CSV final — el ancla temporal y la regla de detección.
- La concentración del 93.9% en 5 patrones sugiere que la optimización del conversor debe priorizar estos EventIDs.
```

**Step 3: Add practical exercise and transition (append to end of file)**

Replace the last paragraph (line 292-293, starting with "**Implicación para el preprocesamiento**") with an expanded version:

```markdown
**Implicación para el preprocesamiento**: Podemos proceder con confianza a diseñar un conversor JSONL → CSV que genere un archivo CSV unificado, donde cada EventID tiene un esquema de columnas fijo y predecible. Esta es la tarea de la siguiente sección.

## Actividad Práctica

### Ejercicio: Análisis Crítico del Fingerprinting

Responde las siguientes preguntas basándote en el análisis de consistencia:

1. **¿Por qué usar MD5 de los nombres de campo ordenados en lugar de comparar conjuntos de campos directamente?** Piensa en eficiencia computacional, almacenamiento, y facilidad de agrupación.

2. **Si dos EventIDs diferentes compartieran exactamente el mismo fingerprint**, ¿qué implicaría para el diseño del conversor CSV? ¿Cómo afectaría al esquema `fields_per_eventid` que se diseña en la siguiente sección?

3. **El análisis reporta 74 campos únicos totales, pero el CSV final tiene 45 columnas.** ¿Qué ocurrió con los campos restantes? Pista: revisa la estrategia de manejo de campos (tabla 4e) y piensa en qué campos se incluyen vs se excluyen en el esquema del conversor.

4. **¿Cómo adaptarías la técnica de fingerprinting para datos NetFlow?** Considera que NetFlow no tiene XML incrustado sino JSON con campos anidados (e.g., `source.ip`, `destination.port`). ¿Qué cambiaría en la función `generate_structure_fingerprint`?

### Resultado esperado

Al finalizar esta sección, deberías comprender:
- Cómo la técnica de fingerprinting valida la consistencia estructural de forma eficiente.
- Que los 19 EventIDs de Sysmon tienen esquemas fijos y deterministas — sin variaciones internas.
- La distribución de campos: 2 universales, 4 comunes, 68 específicos por EventID.
- Por qué esta consistencia permite diseñar un conversor con esquema fijo por EventID.

En la siguiente sección, usaremos estos hallazgos para construir el **pipeline de preprocesamiento** completo: conversión JSONL → CSV para Sysmon (Script 2), NetFlow (Script 3), y limpieza de calidad (Script 4).
```

**Step 4: Build and verify**

Run: `cd /home/researcher/Research/phd-thesis/curso2026 && jupyter-book build .`
Expected: Build succeeds, no errors related to `4-consistencia-estructural.md`

**Step 5: Commit**

```bash
git add sesion-1/4-consistencia-estructural.md
git commit -m "Add diagram, puntos clave, exercises, and transition to 4-consistencia-estructural.md"
```

---

### Task 3: Add pedagogical elements to `6-analisis-calidad-csv.md`

**Files:**
- Modify: `sesion-1/6-analisis-calidad-csv.md` (currently 525 lines)

**Step 1: Add quality analysis pipeline diagram (after line 13, after the tip block)**

Insert after the `{tip}` block:

```markdown

**Pipeline del análisis de calidad:**

```
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────────┐
  │ Paso 1:     │   │ Paso 2:      │   │ Paso 3:      │   │ Paso 4:        │
  │ Carga CSV   │──►│ Inspección   │──►│ Distribución │──►│ Análisis       │
  │ con dtypes  │   │ básica       │   │ de eventos   │   │ temporal       │
  └─────────────┘   └──────────────┘   └──────────────┘   └────────────────┘
                                                                  │
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐          │
  │ Paso 7:     │   │ Paso 6:      │   │ Paso 5:      │          │
  │ Sistema de  │◄──│ Actividad    │◄──│ Relaciones   │◄─────────┘
  │ archivos    │   │ de red       │   │ de procesos  │
  └─────────────┘   └──────────────┘   └──────────────┘
        │
        ▼
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
  │ Paso 8:     │   │ Paso 9:      │   │ Paso 10:     │
  │ Evaluación  │──►│ Readiness    │──►│ Reporte      │
  │ de calidad  │   │ algorítmica  │   │ resumen      │
  └─────────────┘   └──────────────┘   └──────────────┘
```
```

**Step 2: Add "Puntos clave" after Paso 4 temporal analysis (after line 224, after visualization descriptions)**

Insert after the 4 visualization descriptions:

```markdown

**Puntos clave:**
- La ventana de **72 minutos** confirma que el dataset captura un período específico de ejecución del escenario APT, no una monitorización continua — cada evento en esta ventana es potencialmente relevante.
- La tasa de 84 eventos/segundo con picos de 30,563/minuto indica **ráfagas de actividad** que podrían corresponder a fases específicas del ataque (ejecución, movimiento lateral, exfiltración).
- Solo 2 registros sin timestamp (0.0005%) representan una tasa de integridad temporal excepcional para un dataset de esta escala.
- El epoch en milisegundos (`timestamp`) proporciona la **misma resolución temporal** que el dominio NetFlow, habilitando la correlación cruzada en la Sesión 2.
```

**Step 3: Add "Puntos clave" after Paso 8 data quality evaluation (after line 455, after GUID validation paragraph)**

Insert after the consistency section:

```markdown

**Puntos clave:**
- Los altos porcentajes de nulos (hasta 99.998%) **no son un defecto de calidad** — son una consecuencia directa del diseño CSV unificado donde cada fila solo usa las columnas de su EventID.
- El marcado "CRITICAL" para ProcessGuid (31.57% nulos) es un **falso positivo del scoring**: los registros sin ProcessGuid son EID 8/10 que usan `SourceProcessGUID`/`TargetProcessGUID`. La información de proceso está presente, solo con nomenclatura diferente.
- **EventID 255** (1 registro) es el único hallazgo genuino de calidad — un evento no documentado en la especificación oficial de Sysmon que requiere investigación.
- La validación de GUIDs sin llaves demuestra la importancia de adaptar las reglas de validación al dataset real, no a la especificación teórica.
```

**Step 4: Add practical exercise, final puntos clave, and transition (append to end of file)**

Append after the conclusions:

```markdown

**Puntos clave:**
- El dataset es **apto para análisis causal** a pesar de la puntuación de readiness de 32.1% — la cobertura *por EventID* es del 100% para todos los campos relevantes.
- Los indicadores de APT detectados (SystemFailureReporter.exe, puerto 444, PowerShell Bypass) confirman que la simulación generó artefactos realistas de ataque.
- La combinación de GUIDs confiables + cobertura temporal completa + diversidad de EventIDs proporciona los tres pilares necesarios para el análisis de cadenas causales.

## Actividad Práctica

### Ejercicio: Interpretación Crítica de la Calidad de Datos

Responde las siguientes preguntas basándote en el análisis de calidad:

1. **¿Por qué la puntuación de readiness algorítmica de 32.1% es engañosa?** Diseña un método de scoring alternativo que evalúe la cobertura de campos *dentro de cada EventID* en lugar de globalmente. ¿Qué puntuación obtendría el dataset con tu método?

2. **EventID 1 (Process Create) representa solo el 0.28% del dataset (1,023 eventos), pero es el EventID con más campos (23).** ¿Por qué es desproporcionadamente importante para el análisis de amenazas? Piensa en qué información exclusiva aporta (CommandLine, ParentImage, ParentProcessGuid).

3. **El análisis de red muestra 1,378 conexiones al puerto 444, que no es un servicio estándar.** Formula una hipótesis de seguridad: ¿qué tipo de actividad APT podría explicar este tráfico? Considera la proximidad al puerto 443 (HTTPS) y el contexto de la simulación de ataque.

4. **El PID reuse ratio es 1.32 para ProcessGuid/ProcessId.** Diseña una prueba de validación que demuestre por qué usar PIDs (en lugar de GUIDs) para rastreo causal produciría falsos positivos. Describe los datos de entrada y el resultado esperado.

5. **Si tuvieras que elegir solo 5 columnas como "mínimo viable" para entrenar un modelo IDS**, ¿cuáles elegirías y por qué? Considera: identificación del evento, contexto temporal, identificación de proceso, y actividad observable.

### Resultado esperado

Al finalizar esta sección, deberías comprender:
- Cómo evaluar la calidad de un dataset de seguridad distinguiendo artefactos de diseño de problemas reales.
- La importancia de la evaluación *por EventID* frente a la evaluación global en un CSV unificado.
- Los indicadores de actividad APT presentes en los datos y su significancia para la detección.
- Por qué los GUIDs son esenciales para el rastreo causal y los PIDs son insuficientes.

En la **Sesión 2**, usaremos este dataset validado para la **correlación cruzada entre dominios** (Sysmon y NetFlow), aplicando los Scripts 5 y 6 del pipeline para vincular actividad de procesos con flujos de red.
```

**Step 5: Build and verify**

Run: `cd /home/researcher/Research/phd-thesis/curso2026 && jupyter-book build .`
Expected: Build succeeds, no errors related to `6-analisis-calidad-csv.md`

**Step 6: Commit**

```bash
git add sesion-1/6-analisis-calidad-csv.md
git commit -m "Add diagram, puntos clave, exercises, and transition to 6-analisis-calidad-csv.md"
```

---

### Task 4: Final verification and documentation

**Step 1: Full build verification**

Run: `cd /home/researcher/Research/phd-thesis/curso2026 && jupyter-book build . --all`
Expected: Build succeeds for all 24 files, no errors

**Step 2: Verify line counts increased as expected**

Run: `wc -l sesion-1/1-introduccion.md sesion-1/4-consistencia-estructural.md sesion-1/6-analisis-calidad-csv.md`
Expected:
- `1-introduccion.md`: ~120-130 lines (was 82)
- `4-consistencia-estructural.md`: ~360-370 lines (was 293)
- `6-analisis-calidad-csv.md`: ~590-600 lines (was 525)

**Step 3: Commit design docs**

```bash
git add docs/plans/
git commit -m "Add session 1 gap-fill design and implementation plan"
```
