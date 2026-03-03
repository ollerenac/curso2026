# Identificación de Eventos Semilla

**Duración**: 60 minutos

## Script del Pipeline

Esta sección cubre el siguiente script del pipeline de procesamiento:

| Script | Archivo | Tamaño |
|--------|---------|--------|
| **Script 7** | `7_sysmon_seed_event_extractor.py` | 22.7 KB |

### Script 7: Extractor de Eventos Semilla

Extrae todos los eventos Sysmon con EventID 1 (Process Creation), 11 (File Create) y 23 (File Delete) del CSV de un run hacia un archivo separado para marcaje manual por el analista. Los eventos extraídos se enriquecen con columnas `Seed_Event`, `Tactic` y `Technique` vacías, listas para ser completadas en la fase de etiquetado manual.

- **Entrada**: `sysmon-run-XX-hpc.csv` (preferido, con columnas de ProcessContext) o `sysmon-run-XX.csv` (fallback)
- **Salida**: `all_target_events_run-XX.csv` — todos los eventos candidatos con columnas de etiquetado
- **Criterio de selección**: EventID ∈ {1, 11, 23} — los tipos de evento más indicativos de actividad maliciosa en un APT

## Contenido

*Por desarrollar.*
