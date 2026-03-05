# Limpieza de Calidad de Datos Sysmon (Script 4)

**Duración**: 30 minutos

## Contexto: ¿Qué descubrimos en el análisis de calidad?

En la sección anterior, el análisis de consistencia semántica (Paso 8d) verificó las dos invariantes fundamentales de ProcessGuid:

> **Invariante 1**: Un ProcessGuid → exactamente 1 ProcessId
>
> **Invariante 2**: Un ProcessGuid → exactamente 1 Image (ruta del ejecutable)

Los resultados confirmaron **0 violaciones PID** (cada GUID mapea a un único PID), pero detectaron **10 violaciones de Image**: 10 ProcessGuids que aparecen con 2 o más rutas de ejecutable diferentes. De estas, 8 son falsos positivos (rutas versionadas vs symlink de Elastic Agent) y 2 son colisiones genuinas (`svchost.exe` vs `dxgiadaptercache.exe` compartiendo GUID).

Si no se corrigen, estas violaciones contaminarán los análisis de causalidad de los Scripts 7 y 8 (etiquetado). El Script 4 automatiza la detección y corrección de estas inconsistencias.

## El problema: Violaciones de ProcessGuid

Las violaciones de Image detectadas tienen dos causas raíz:

| Causa | GUIDs | Naturaleza |
|-------|-------|------------|
| **Ruta versionada vs symlink** | 8 | Falso positivo — dos rutas al mismo binario |
| **Colisión de GUID** | 2 | Genuina — ejecutables diferentes comparten GUID |

Además, en otros runs del dataset pueden aparecer violaciones adicionales causadas por el prefijo `\\?\` que Windows usa para rutas extendidas, creando falsos positivos donde `C:\Windows\cmd.exe` y `\\?\C:\Windows\cmd.exe` son realmente la misma imagen.

## Arquitectura del pipeline de limpieza

El Script 4 es un **orquestador** que ejecuta 5 sub-scripts en secuencia:

```
┌─────────────────────────────────────────────────────────────┐
│            Script 4: Pipeline de Limpieza                    │
│                                                              │
│  Paso 1  ┌──────────────────────────────────┐               │
│  ───────►│ find_processguid_pid_violations   │               │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 2  ┌──────────────────────────────────┐               │
│  ───────►│ find_processguid_image_violations │               │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 3  ┌──────────────────────────────────┐               │
│  ───────►│ normalize_path_duplicates         │  ← \\?\ fix  │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 4  ┌──────────────────────────────────┐               │
│  ───────►│ extract_violation_events          │               │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 5  ┌──────────────────────────────────┐               │
│   (opt)  │ Manual editing (LibreOffice Calc) │  ← Humano    │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 6  ┌──────────────────────────────────┐               │
│  ───────►│ apply_violation_fixes             │               │
│          └──────────────────────────────────┘               │
│                                                              │
│  Input:  sysmon-run-XX.csv                                   │
│  Output: sysmon-run-XX.csv (corregido in-place)              │
└─────────────────────────────────────────────────────────────┘
```

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
         "--run-id", run_id],
        "Detecting ProcessGuid-PID violations"
    )

    # Paso 2: Detectar violaciones de Image
    run_command(
        [sys.executable, str(QUALITY_DIR / "find_processguid_image_violations.py"),
         "--run-id", run_id],
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
         "--run-id", run_id],
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
         "--run-id", run_id],
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
- Este paso introduce un componente **human-in-the-loop**: el analista revisa las violaciones y decide cómo corregirlas (ej: asignar el PID correcto, eliminar registros duplicados).
- Las columnas `_original_row_index` y `_row_hash` permiten rastrear cada corrección hasta su registro original en el CSV.

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
           "--run-id", run_id]

    if dry_run:
        cmd.append("--dry-run")
    if verbose:
        cmd.append("--verbose")

    run_command(cmd, "Applying violation fixes")
    return True
```

## Uso del script

```bash
# Flujo completo: detectar, normalizar, extraer, editar, aplicar
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05

# Solo detección (sin correcciones)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --detect-only

# Solo aplicar correcciones (si ya se editó el archivo de violaciones)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --apply-only

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
- Por qué la corrección incluye un paso **human-in-the-loop** en lugar de ser completamente automática.
- La importancia de las columnas de trazabilidad (`_original_row_index`, `_row_hash`) para auditar las correcciones.

En la **siguiente sección** aplicamos la misma conversión JSONL → CSV al dominio NetFlow, donde el reto no es parsear XML sino aplanar una jerarquía JSON de múltiples niveles en 39 columnas fijas.
