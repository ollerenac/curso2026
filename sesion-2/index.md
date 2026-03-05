# Sesión 2: Preprocesamiento y Calidad

**Duración**: 3 horas

## Objetivos

- Transformar datos JSONL en datasets CSV estructurados para ambos dominios
- Aplicar limpieza de calidad sobre el CSV de Sysmon
- Evaluar la calidad del CSV resultante y su readiness para ML

## Contenido

1. [Preprocesamiento Sysmon: De JSONL a CSV](1-preprocesamiento-sysmon.md) (60 min) — Scripts 2, 4 del pipeline
2. [Preprocesamiento NetFlow: De JSONL a CSV](2-preprocesamiento-netflow.md) (30 min) — Script 3 del pipeline
3. [Análisis de Calidad del CSV](3-analisis-calidad-csv.md) (75 min) — Notebook 2c

## Scripts del Pipeline

Esta sesión cubre los scripts de **preprocesamiento** del pipeline:

| Script | Archivo | Función |
|--------|---------|---------|
| Script 2 | `2_sysmon_csv_creator.py` | Conversión Sysmon JSONL → CSV |
| Script 3 | `3_netflow_csv_creator.py` | Conversión NetFlow JSONL → CSV |
| Script 4 | `4_sysmon_data_cleaner.py` | Limpieza de violaciones ProcessGuid |
