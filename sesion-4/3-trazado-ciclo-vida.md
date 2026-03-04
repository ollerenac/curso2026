# Trazado Automático de Ciclo de Vida

**Duración**: 60 minutos

## Script del Pipeline

Esta sección cubre el siguiente script del pipeline de procesamiento:

| Script | Archivo | Tamaño |
|--------|---------|--------|
| **Script 8** | `8_sysmon_attack_lifecycle_tracer.py` | 115 KB |

### Script 8: Trazador de Ciclo de Vida de Ataques

Toma los eventos semilla seleccionados manualmente (Script 7) y traza sus cadenas de ataque completas a través de los datos de Sysmon. Para EventID 1 (Process Creation), realiza correlación basada en ProcessGuid para descubrir procesos hijo y eventos derivados. Para EventID 11/23 (File Create/Delete), realiza análisis individual de cada evento.

- **Entrada**: Eventos semilla marcados desde `all_target_events_run-XX.csv` + `sysmon-run-XX-hpc.csv`
- **Salida**: Timelines individuales por evento semilla, timeline unificado del grupo, eventos trazados con metadatos de táctica exportados a CSV
- **Técnicas**: Correlación por ProcessGuid (árbol de procesos), análisis multi-EventID, visualización temporal con metadatos MITRE ATT&CK
- **Módulos compartidos**: `apt_config`, `apt_plotting_utils`, `apt_path_utils`

## Contenido

*Por desarrollar.*
