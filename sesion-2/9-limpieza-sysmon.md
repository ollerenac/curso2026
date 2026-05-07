# Limpieza de Calidad de Datos Sysmon (Script 9)

**Duración**: 30 minutos

```{admonition} Script de trabajo
:class: note

**Orquestador**: `sesion-2/9_sysmon_data_cleaner.py`
**Sub-scripts**: `sesion-2/quality/` (detección, normalización, extracción, aplicación)
```

## Contexto: ¿Qué descubrimos en el análisis de calidad?

En la sección anterior, el análisis de consistencia semántica (Paso 8d) verificó las dos invariantes fundamentales de ProcessGuid:

> **Invariante 1**: Un ProcessGuid → exactamente 1 ProcessId
>
> **Invariante 2**: Un ProcessGuid → exactamente 1 Image (ruta del ejecutable)

Los resultados del análisis de k=1 (par ProcessGuid) confirmaron que **ningún GUID real viola el Invariante 1** — el único "violador" es el GUID centinela ∅, que acumula eventos de procesos no identificados en el arranque. Para el Invariante 2 se detectaron **28 GUIDs con múltiples Images** (2.07% del dataset), clasificados en cuatro categorías: artefactos de boot (`<unknown process>`), prefijo de ruta `\\?\`, variantes de Elastic Agent, y 2 colisiones genuinas.

Si no se corrigen, estas violaciones contaminarán los análisis de causalidad de los pasos de etiquetado. El Script 9 automatiza la detección y corrección de estas inconsistencias para el par k=1.

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
python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01

# Solo detección (sin correcciones)
python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --detect-only

# Solo aplicar correcciones (si ya se editó el archivo de violaciones)
python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --apply-only

# Saltar normalización de rutas (para inspeccionar violaciones sin filtrar)
python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --skip-normalization

# Vista previa de cambios sin aplicar
python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --dry-run --verbose
```

---

## Diseño interno: cómo extender los scripts a otros pares GUID

Los scripts actuales cubren únicamente el par **k=1** (columna `ProcessGuid`). El análisis del Paso 8f demostró que k=2, k=3 y k=4 también tienen violaciones. Para extender los scripts es necesario entender su algoritmo central y qué cambia en cada par.

### El algoritmo de detección (pasos 1-2)

Ambos detectores — `find_processguid_pid_violations.py` y `find_processguid_image_violations.py` — siguen el mismo algoritmo de tres fases:

**Fase A — Construir el mapa GUID → conjunto**

El CSV se lee en chunks de 100 000 filas para no agotar la memoria. Para cada chunk, se acumula un `defaultdict(set)` que guarda todas las combinaciones únicas de (PID o Image, Computer, RunID) vistas para cada GUID:

```python
from collections import defaultdict
guid_to_info = defaultdict(set)

for chunk in pd.read_csv(sysmon_file,
        usecols=['ProcessGuid', 'ProcessId', 'Image', 'Computer'],
        chunksize=100_000, low_memory=False):

    chunk = chunk.dropna(subset=['ProcessGuid', 'ProcessId'])

    for guid in chunk['ProcessGuid'].unique():
        guid_rows = chunk[chunk['ProcessGuid'] == guid]
        for _, row in guid_rows.iterrows():
            guid_to_info[guid].add((
                row['ProcessId'], row['Image'], row['Computer'], run_id
            ))
```

El uso de `set` deduplica automáticamente: si el mismo (PID, Image, Computer) aparece en 10 000 filas, solo ocupa una entrada en el conjunto.

**Fase B — Identificar violadores**

Una vez procesado todo el archivo, se recorre el diccionario. Un GUID viola el invariante si su conjunto contiene más de un valor único del campo objetivo:

```python
# Invariante 1: el conjunto tiene más de 1 PID distinto
unique_pids = set(pid for pid, _, _, _ in info_set)
if len(unique_pids) > 1:
    # → violación: este GUID se mapea a múltiples PIDs

# Invariante 2: el conjunto tiene más de 1 Image distinta (case-insensitive)
unique_images = set(img.lower() for img, _, _, _ in info_set if pd.notna(img))
if len(unique_images) > 1:
    # → violación: este GUID se mapea a múltiples Images
```

**Fase C — Escribir el CSV de salida**

Por cada GUID violador se emite una fila por cada entrada de su conjunto — es decir, una fila por cada (GUID, PID/Image, Computer, RunID) distinto. Esto le da al analista la lista completa de valores contradictorios que debe resolver.

### Por qué los scripts actuales cubren solo k=1

Los scripts leen únicamente la columna `ProcessGuid` sin aplicar ningún filtro de EventID. Esto captura k=1 de forma implícita, pero ignora los otros tres pares porque sus GUIDs viven en columnas con nombres diferentes:

| Par | Columna GUID | Columna PID | Columna Image | Dominio (filtro EventID) |
|-----|-------------|-------------|---------------|--------------------------|
| k=1 | `ProcessGuid` | `ProcessId` | `Image` | todos los EID (sin filtro) |
| k=2 | `ParentProcessGuid` | `ParentProcessId` | `ParentImage` | solo EID = 1 |
| k=3 | `SourceProcessGUID` | `SourceProcessId` | `SourceImage` | solo EID ∈ {8, 10} |
| k=4 | `TargetProcessGUID` | `TargetProcessId` | `TargetImage` | solo EID ∈ {8, 10} |

El filtro de EventID es necesario porque `ParentProcessGuid`, `SourceProcessGUID` y `TargetProcessGUID` solo están poblados en un subconjunto de eventos. Leer filas donde la columna es vacía (NaN) no produce falsos positivos gracias al `dropna`, pero sí desperdicia ciclos de CPU en cada chunk.

### Qué cambiar para extender a k=2

El cambio es mínimo: tres constantes en la parte superior del script y un filtro de chunk. Ejemplo para k=2:

```python
# Constantes a cambiar
GUID_COL = 'ParentProcessGuid'   # antes: 'ProcessGuid'
PID_COL  = 'ParentProcessId'     # antes: 'ProcessId'
IMG_COL  = 'ParentImage'         # antes: 'Image'
EID_FILTER = [1]                 # antes: ninguno

# Lectura con filtro de dominio
for chunk in pd.read_csv(sysmon_file,
        usecols=['EventID', GUID_COL, PID_COL, IMG_COL, 'Computer'],
        chunksize=100_000, low_memory=False):

    chunk = chunk[chunk['EventID'].isin(EID_FILTER)]   # ← línea nueva
    chunk = chunk.dropna(subset=[GUID_COL, PID_COL])
    # ... resto igual, usando GUID_COL / PID_COL / IMG_COL
```

Para k=3 y k=4 el mismo patrón aplica cambiando las constantes y usando `EID_FILTER = [8, 10]`.

### Qué cambiar en `extract_violation_events.py`

El extractor une el archivo de violaciones con el CSV original mediante la clave `(Computer, ProcessId)`. Para los otros pares, la clave cambia según qué columna PID contiene el proceso violador:

| Par | Clave de join actual | Clave de join necesaria |
|-----|---------------------|------------------------|
| k=1 | `(Computer, ProcessId)` | igual |
| k=2 | `(Computer, ProcessId)` | `(Computer, ParentProcessId)` |
| k=3 | `(Computer, ProcessId)` | `(Computer, SourceProcessId)` |
| k=4 | `(Computer, ProcessId)` | `(Computer, TargetProcessId)` |

Además, para k=2 solo interesan los eventos EID=1 (Process Create) — son los únicos que tienen `ParentProcessGuid`. Para k=3/k=4 solo interesan EID ∈ {8, 10}.

El extractor actual no aplica ningún filtro de EventID al escanear el CSV, por lo que también habría que añadir un filtro de chunk antes del merge:

```python
# Para k=3 — solo EID ∈ {8, 10}
chunk = chunk[chunk['EventID'].isin([8, 10])]
chunk_matched = chunk.merge(
    violation_keys,                      # (Computer, SourceProcessId)
    left_on=['Computer', 'SourceProcessId'],
    right_on=['Computer', 'SourceProcessId'],
    how='inner'
)
```

`apply_violation_fixes.py` no necesita cambios: trabaja sobre el archivo de violaciones ya editado y aplica cualquier columna que haya cambiado valor — es genérico por diseño.

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

### Entrega

Sube tu notebook completado (`8_sysmon_csv_exploratory_analysis.ipynb`) y los scripts modificados al siguiente Google Drive:

📁 [Carpeta de entregas — Sección 9](https://drive.google.com/drive/folders/1BqPQo_xX1Ud7Vib37roVwyx7JuCk3uhw?usp=sharing)

Instrucciones:
1. Entra al Drive con tu cuenta institucional.
2. Crea una carpeta con tu nombre completo usando guiones bajos como separador (ej. `Juan_Garcia_Lopez`).
3. Deposita tus archivos dentro de esa carpeta.
