# Sesión 2: Preprocesamiento y Calidad

**Duración**: 3 horas

## Objetivos

- Transformar datos Sysmon JSONL en un CSV tabular estructurado
- Evaluar la calidad del CSV resultante y su readiness para ML
- Corregir problemas de integridad detectados en el análisis de calidad
- Transformar datos NetFlow JSONL en un CSV tabular estructurado

## Contenido

1. [Preprocesamiento Sysmon: De JSONL a CSV](1-preprocesamiento-sysmon.md) (60 min) — Script 2 del pipeline
2. [Análisis de Calidad del CSV](2-analisis-calidad-csv.md) (60 min) — Notebook 2c
3. [Limpieza de Datos Sysmon](3-limpieza-sysmon.md) (30 min) — Script 4 del pipeline
4. [Preprocesamiento NetFlow: De JSONL a CSV](4-preprocesamiento-netflow.md) (30 min) — Script 3 del pipeline

## Scripts del Pipeline

Esta sesión cubre los scripts de **preprocesamiento** del pipeline:

| Script | Archivo | Función |
|--------|---------|---------|
| Script 2 | `2_sysmon_csv_creator.py` | Conversión Sysmon JSONL → CSV |
| Script 4 | `4_sysmon_data_cleaner.py` | Limpieza de violaciones ProcessGuid |
| Script 3 | `3_netflow_csv_creator.py` | Conversión NetFlow JSONL → CSV |

## Flujo pedagógico

```
Crear CSV         Analizar calidad      Limpiar            Crear CSV
  Sysmon      →     del CSV         →   problemas      →    NetFlow
(Script 2)        (Notebook 2c)       (Script 4)         (Script 3)
```

El orden refleja el mismo patrón de la Sesión 1: primero producimos los datos, luego los analizamos, y finalmente corregimos los problemas que encontramos.
