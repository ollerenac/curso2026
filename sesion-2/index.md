# Sesión 2: Calidad de Datos y Marco Teórico

**Duración**: 3 horas

## Objetivos

- Validar la correlación cruzada entre los dominios Sysmon y NetFlow
- Comprender el framework MITRE ATT&CK para clasificación de amenazas
- Establecer la teoría de etiquetado para datasets dual-domain

## Contenido

1. [Análisis de Calidad y Correlación Cruzada](1-analisis-calidad.md) (75 min) — Scripts 5-6 del pipeline
2. [Framework de Clasificación de Amenazas](2-framework-clasificacion.md) (45 min)
3. [Teoría de Etiquetado](3-teoria-etiquetado.md) (60 min)

## Scripts del Pipeline

Esta sesión cubre los scripts de **correlación** del pipeline de procesamiento:

| Script | Archivo | Función |
|--------|---------|---------|
| Script 5 | `5_enhanced_temporal_causation_correlator.py` | Correlación temporal entre NetFlow y Sysmon |
| Script 6 | `6_comprehensive_correlation_analysis.py` | Visualización y estadísticas de correlación |
