# Sesión 5: Generación de Datasets Finales

**Duración**: 3 horas

## Objetivos

- Generar el dataset etiquetado de eventos del sistema (Sysmon)
- Generar el dataset etiquetado de tráfico de red (NetFlow)
- Validar la calidad de los datasets producidos

## Contenido

1. [Dataset de Eventos del Sistema](1-dataset-eventos-sistema.md) (60 min) — Script 9 del pipeline
2. [Dataset de Tráfico de Red](2-dataset-trafico-red.md) (90 min) — Script 10 del pipeline
3. [Validación de Calidad](3-validacion-calidad.md) (30 min)

## Scripts del Pipeline

Esta sesión cubre los scripts de **generación de datasets finales** del pipeline:

| Script | Archivo | Función |
|--------|---------|---------|
| Script 9 | `9_create_labeled_sysmon_dataset.py` | Crear dataset Sysmon etiquetado con tácticas MITRE |
| Script 10 | `10_create_labeled_netflow_dataset.py` | Crear dataset NetFlow etiquetado vía correlación |
