# Dataset de Eventos del Sistema

**Duración**: 60 minutos

## Script del Pipeline

Esta sección cubre el siguiente script del pipeline de procesamiento:

| Script | Archivo | Tamaño |
|--------|---------|--------|
| **Script 9** | `9_create_labeled_sysmon_dataset.py` | 34.3 KB |

### Script 9: Generador de Dataset Sysmon Etiquetado

Crea el dataset final etiquetado de Sysmon (`sysmon-run-XX-labeled.csv`) fusionando el CSV de Sysmon enriquecido con HPC (`sysmon-run-XX-hpc.csv`) y los eventos trazados con tácticas (`traced_sysmon_events_with_tactics_v2.csv`) para añadir etiquetas MITRE ATT&CK (`Tactic` y `Technique`).

- **Entrada**: `sysmon-run-XX-hpc.csv` + `traced_sysmon_events_with_tactics_v2.csv` (del Script 8)
- **Salida**: `sysmon-run-XX-labeled.csv` — dataset completo con columnas `Tactic` y `Technique`
- **Visualizaciones**: Timelines v2 (simple y coloreado por táctica) de todos los eventos maliciosos
- **Mapa de colores**: 15 colores para las tácticas MITRE ATT&CK (Reconnaissance → Impact)

## Contenido

*Por desarrollar.*
