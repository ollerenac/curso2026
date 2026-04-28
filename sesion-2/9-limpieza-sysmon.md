# Limpieza de Calidad de Datos Sysmon (Script 4)

**Duración**: 30 minutos

```{admonition} Script de trabajo
:class: note

**Orquestador**: `scripts/pipeline/4_sysmon_data_cleaner.py`
**Sub-scripts**: `scripts/pipeline/quality/` (detección, normalización, extracción, aplicación)
```

## Contexto: ¿Qué descubrimos en el análisis de calidad?

En la sección anterior, el análisis de consistencia semántica (Paso 8d) verificó las dos invariantes fundamentales de ProcessGuid:

> **Invariante 1**: Un ProcessGuid → exactamente 1 ProcessId
>
> **Invariante 2**: Un ProcessGuid → exactamente 1 Image (ruta del ejecutable)

Los resultados confirmaron **0 violaciones PID** (cada GUID mapea a un único PID), pero detectaron **28 violaciones de Image**: 28 ProcessGuids que aparecen con 2 o más rutas de ejecutable diferentes, afectando 7,518 eventos (2.07% del dataset).

Si no se corrigen, estas violaciones contaminarán los análisis de causalidad de los Scripts 7 y 8 (etiquetado). El Script 4 automatiza la detección y corrección de estas inconsistencias.

## El problema: Violaciones de ProcessGuid

Las violaciones de Image detectadas se clasifican en 4 categorías:

| Categoría | GUIDs | Naturaleza |
|-----------|-------|------------|
| **Artefacto `<unknown process>`** | 17 | Sysmon no pudo determinar el ejecutable al momento del registro |
| **Prefijo `\\?\`** | 2 | Falso positivo — Windows usa `\\?\` para rutas extendidas |
| **Mismo binario, ruta diferente** | 7 | Falso positivo — Elastic Agent con ruta real vs symlink |
| **Ejecutables diferentes** | 2 | Genuina — `svchost.exe` vs `dxgiadaptercache.exe` comparten GUID |

## Arquitectura del pipeline de limpieza

El Script 4 es un **orquestador** que ejecuta 5 sub-scripts en secuencia. Antes de comenzar, verifica que existan tanto el CSV de Sysmon de entrada como los 5 sub-scripts en `pipeline/quality/`. Si falta algún prerequisito, el script termina con un mensaje indicando qué pasos ejecutar primero.

```
┌──────────────────────────────────────────────────────────────────┐
│                    VERIFICACIÓN DE PREREQUISITOS                  │
│  Verifica: sysmon-run-XX.csv existe + 5 sub-scripts existen     │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  PASO 1-2: DETECCIÓN DE VIOLACIONES                              │
│  ┌─────────────────────────────────────┐                         │
│  │ find_processguid_pid_violations.py  │→ exploration/violations/│
│  │   --run {run_num}                   │  pid_violations_runXX   │
│  └─────────────────────────────────────┘                         │
│  ┌─────────────────────────────────────┐                         │
│  │ find_processguid_image_violations.py│→ exploration/violations/│
│  │   --run {run_num}                   │  image_violations_runXX │
│  └─────────────────────────────────────┘                         │
│  ← Si --detect-only: TERMINA AQUÍ                                │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  PASO 3: NORMALIZACIÓN DE RUTAS                                  │
│  ┌─────────────────────────────────────┐                         │
│  │ normalize_path_duplicates.py        │  Elimina falsos         │
│  │   {image_violations_file}           │  positivos \\?\         │
│  └─────────────────────────────────────┘                         │
│  Renombra _normalized.csv → original                             │
│  ← Si --skip-normalization: SALTA este paso                     │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  PASO 4: EXTRACCIÓN DE EVENTOS                                   │
│  ┌─────────────────────────────────────┐                         │
│  │ extract_violation_events.py         │→ dataset/run-XX-apt-Y/  │
│  │   --run {run_num}                   │  sysmon-run-XX-         │
│  └─────────────────────────────────────┘  violations.csv         │
│  Añade: _original_row_index + _row_hash                          │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  PASO 5: 🧑 EDICIÓN MANUAL (HUMAN-IN-THE-LOOP)                  │
│                                                                   │
│  1. Abre LibreOffice Calc automáticamente                        │
│  2. El analista corrige valores en el CSV de violaciones         │
│  3. NO tocar _original_row_index ni _row_hash                   │
│  4. Pulsar Enter en terminal al terminar                         │
│                                                                   │
│  ← Si --apply-only: SALTA pasos 1-5, usa archivo existente      │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  PASO 6: APLICACIÓN DE CORRECCIONES                              │
│  ┌─────────────────────────────────────┐                         │
│  │ apply_violation_fixes.py            │  Modifica in-place:     │
│  │   --run {run_num}                   │  sysmon-run-XX.csv      │
│  │   [--dry-run] [--verbose]           │                         │
│  └─────────────────────────────────────┘                         │
│  Seguridad: backup automático + verificación hash por fila       │
└──────────────────────────────────────────────────────────────────┘
```

### Flujo de datos (I/O)

```
INPUT:
  dataset/run-XX-apt-Y/sysmon-run-XX.csv

INTERMEDIOS (generados por pasos 1-4):
  exploration/violations/processguid_pid_violations_runXX.csv      ← Paso 1
  exploration/violations/processguid_image_violations_runXX.csv    ← Paso 2
  exploration/violations/..._normalized.csv → renombrado           ← Paso 3
  dataset/run-XX-apt-Y/sysmon-run-XX-violations.csv                ← Paso 4

OUTPUT:
  dataset/run-XX-apt-Y/sysmon-run-XX.csv                           (modificado in-place)
  dataset/run-XX-apt-Y/sysmon-run-XX.csv.backup_YYYYMMDD_HHMMSS   (backup automático)
```

Nótese que los archivos de detección (pasos 1-2) se almacenan en `exploration/violations/`, separados del dataset, mientras que el archivo de violaciones editables (paso 4) se genera junto al CSV original en `dataset/`. Esta separación es intencional: los archivos de detección son artefactos de diagnóstico, mientras que el archivo de violaciones es el que el analista edita y el paso 6 consume.

## Paso 1-2: Detección de violaciones

Los dos primeros pasos analizan el CSV de Sysmon buscando GUIDs que violen la regla de unicidad:

```python
def detect_violations(run_id) -> bool:
    """
    Ejecuta los scripts de detección de violaciones PID e Image.
    Genera archivos CSV con las violaciones encontradas en exploration/violations/.
    """
    # Paso 1: Detectar violaciones de PID
    run_command(
        [sys.executable, str(QUALITY_DIR / "find_processguid_pid_violations.py"),
         "--run", run_id],
        "Detecting ProcessGuid-PID violations"
    )

    # Paso 2: Detectar violaciones de Image
    run_command(
        [sys.executable, str(QUALITY_DIR / "find_processguid_image_violations.py"),
         "--run", run_id],
        "Detecting ProcessGuid-Image violations"
    )

    return True
```

**Archivos generados:**
```
exploration/violations/
├── processguid_pid_violations_runXX.csv
└── processguid_image_violations_runXX.csv
```

## Paso 3: Normalización de rutas

La normalización elimina falsos positivos causados por el prefijo de rutas extendidas de Windows:

```python
def normalize_violations(run_id, skip_normalization) -> bool:
    """
    Normaliza duplicados causados por el prefijo '\\\\?\\' de Windows.

    Ejemplo:
    - Antes: {GUID} → ['C:\\Windows\\cmd.exe', '\\\\?\\C:\\Windows\\cmd.exe']
    - Después: {GUID} → ['C:\\Windows\\cmd.exe']  (ya no es violación)
    """
    if skip_normalization:
        return True

    run_command(
        [sys.executable, str(QUALITY_DIR / "normalize_path_duplicates.py"),
         violations_file],
        "Normalizing path duplicates"
    )
    return True
```

## Paso 4-5: Extracción y edición manual

Las violaciones que no son falsos positivos se extraen a un archivo CSV separado para revisión manual:

```python
def extract_violations(run_id) -> bool:
    """
    Extrae los eventos con violaciones a un archivo separado para edición.
    """
    run_command(
        [sys.executable, str(QUALITY_DIR / "extract_violation_events.py"),
         "--run", run_id],
        "Extracting violation events"
    )
    return True


def manual_editing_pause(violations_file, auto_skip) -> bool:
    """
    Pausa interactiva para revisión manual de las violaciones.
    Opcionalmente abre LibreOffice Calc para editar el CSV.

    El archivo contiene columnas adicionales:
    - _original_row_index: Posición en el CSV original (para trazabilidad)
    - _row_hash: Hash del registro original (para validación de integridad)
    """
    if auto_skip:
        return True

    print(f"\nViolations file ready for manual review: {violations_file}")
    response = input("Open in LibreOffice Calc? [y/N]: ")
    if response.lower() == 'y':
        subprocess.run(['libreoffice', '--calc', str(violations_file)])

    input("Press Enter when done editing...")
    return True
```

**Puntos clave:**
- Este paso introduce un componente **human-in-the-loop**: el script abre LibreOffice Calc automáticamente con `subprocess.Popen()` (no bloquea el proceso) y luego espera con `input()` hasta que el analista pulse Enter en la terminal.
- El analista debe: corregir valores de `Image` o `ProcessGuid` en las filas con violaciones, opcionalmente eliminar filas que considere irrecuperables, y **nunca** modificar las columnas `_original_row_index` ni `_row_hash` — son la clave de trazabilidad que permite al paso 6 ubicar y verificar cada fila en el CSV original.
- Si LibreOffice no está instalado, el script avisa y espera igualmente a que el analista edite el archivo con la herramienta que prefiera.

## Paso 6: Aplicación de correcciones

Finalmente, las correcciones manuales se aplican al CSV original:

```python
def apply_fixes(run_id, dry_run, verbose) -> bool:
    """
    Aplica las correcciones del archivo de violaciones al CSV original.

    Args:
        run_id: Identificador del run
        dry_run: Si True, solo muestra los cambios sin aplicarlos
        verbose: Si True, muestra cada cambio individual
    """
    cmd = [sys.executable, str(QUALITY_DIR / "apply_violation_fixes.py"),
           "--run", run_id]

    if dry_run:
        cmd.append("--dry-run")
    if verbose:
        cmd.append("--verbose")

    run_command(cmd, "Applying violation fixes")
    return True
```

**Mecanismos de seguridad:**

El sub-script `apply_violation_fixes.py` incorpora dos protecciones antes de modificar el CSV original:

1. **Backup automático**: Antes de aplicar cualquier cambio, crea una copia con marca temporal:
   ```
   sysmon-run-05.csv.backup_20260305_143052
   ```
   Si algo sale mal, se puede restaurar con `cp sysmon-run-05.csv.backup_... sysmon-run-05.csv`.

2. **Verificación de hash por fila**: Para cada fila del archivo de violaciones, recalcula el hash MD5 desde el CSV original y lo compara con `_row_hash`. Si no coinciden — porque el CSV original fue modificado entre la extracción y la aplicación — la fila se **salta** con un warning. Esto impide aplicar correcciones obsoletas sobre datos que ya cambiaron.

## Modos de ejecución

El orquestador soporta múltiples modos que permiten ejecutar el pipeline completo o solo fases específicas:

| Flag | Pasos ejecutados | Caso de uso |
|------|-----------------|-------------|
| *(ninguno)* | 1→2→3→4→5→6 | Flujo completo interactivo |
| `--detect-only` | 1→2 | Inspeccionar violaciones sin corregir |
| `--apply-only` | 6 | Aplicar correcciones sobre archivo ya editado |
| `--dry-run` | 6 (sin escritura) | Vista previa de cambios (implica `--apply-only`) |
| `--skip-normalization` | 1→2→(salta 3)→4→5→6 | Mantener prefijos `\\?\` para inspección |

### Uso del script

```bash
# Flujo completo: detectar, normalizar, extraer, editar, aplicar
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05

# Solo detección (sin correcciones)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --detect-only

# Solo aplicar correcciones (si ya se editó el archivo de violaciones)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --apply-only

# Saltar normalización de rutas (para inspeccionar violaciones sin filtrar)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --skip-normalization

# Vista previa de cambios sin aplicar
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --dry-run --verbose
```

---

## Actividad Práctica

### Ejercicio: Violaciones de ProcessGuid

Dado el siguiente fragmento de datos de Sysmon:

| ProcessGuid | ProcessId | Image |
|-------------|-----------|-------|
| {ABC-123} | 4520 | `C:\Windows\System32\cmd.exe` |
| {ABC-123} | 4520 | `\\?\C:\Windows\System32\cmd.exe` |
| {DEF-456} | 1234 | `C:\Tools\nc.exe` |
| {DEF-456} | 5678 | `C:\Tools\nc.exe` |

1. **¿Cuántas violaciones hay y de qué tipo?** Identifica si son violaciones PID, Image, o ambas.
2. **¿Cuál de ellas se resolvería automáticamente** con la normalización del prefijo `\\?\`?
3. **¿Cuál requiere intervención manual?** ¿Qué información adicional necesitarías para decidir la corrección?

### Resultado Esperado

Al finalizar esta sección, deberías comprender:

- Qué tipos de violaciones de integridad pueden existir en el CSV de Sysmon y cómo se detectan.
- El patrón de diseño **orquestador** que coordina múltiples sub-scripts en un pipeline secuencial.
- El flujo de datos completo: qué archivos se generan en cada paso, dónde se almacenan, y cómo fluyen de un paso al siguiente.
- Los diferentes modos de ejecución (`--detect-only`, `--apply-only`, `--dry-run`) y cuándo usar cada uno.
- Por qué la corrección incluye un paso **human-in-the-loop** en lugar de ser completamente automática.
- La importancia de los mecanismos de seguridad (backup automático, verificación de hash) y las columnas de trazabilidad (`_original_row_index`, `_row_hash`) para auditar las correcciones.

En la **siguiente sección** aplicamos la misma conversión JSONL → CSV al dominio NetFlow, donde el reto no es parsear XML sino aplanar una jerarquía JSON de múltiples niveles en 39 columnas fijas.
