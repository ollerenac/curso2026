# Análisis de Calidad y Correlación Cruzada

**Duración**: 75 minutos

## Scripts del Pipeline

Esta sección cubre los siguientes scripts del pipeline de procesamiento:

| Script | Archivo | Tamaño |
|--------|---------|--------|
| **Script 5** | `5_enhanced_temporal_causation_correlator.py` | 137 KB |
| **Script 6** | `6_comprehensive_correlation_analysis.py` | 35.8 KB |

### Script 5: Correlador de Causación Temporal

Motor de correlación dual-domain (v3.1) que implementa análisis de causación temporal entre flujos NetFlow y eventos Sysmon del host. Analiza 4 tipos de ciclo de vida de procesos (Start-End, No-End, No-Start, No-Bounds) con múltiples escenarios de solapamiento temporal, calculando tasas de atribución y estadísticas de timing.

- **Entrada**: `sysmon-run-XX.csv` + `netflow-run-XX.csv`
- **Salida**: Resultados JSON, gráficos de atribución, distribución de escenarios y análisis temporal en `analysis/correlation-analysis-v4/apt-X/run-XX/`
- **Modos**: Análisis individual por run, batch de runs de alto rendimiento (≥90% atribución), batch completo

### Script 6: Análisis Comprehensivo de Correlación

Suite de post-procesamiento que genera visualizaciones y reportes a partir de los resultados JSON del Script 5 a través de todos los runs APT.

- **Entrada**: Resultados JSON del Script 5 en `analysis/correlation-analysis-v4/`
- **Salida**: Panel de 8 gráficos (PNG/PDF), timeline de atribución por evento, CSV de estadísticas, reporte ejecutivo en Markdown (`CORRELATION_SUMMARY_REPORT.md`)

## Contenido

*Por desarrollar.*
