# Sesión 3: Etiquetado Manual Guiado

**Duración**: 3 horas

## Objetivos

- Identificar eventos semilla en telemetría Sysmon
- Ejecutar el proceso de etiquetado manual paso a paso
- Automatizar el trazado de ciclo de vida de ataques

## Contenido

1. [Identificación de Eventos Semilla](1-eventos-semilla.md) (60 min) — Script 7 del pipeline
2. [Proceso de Etiquetado Manual](2-etiquetado-manual.md) (60 min)
3. [Trazado Automático de Ciclo de Vida](3-trazado-ciclo-vida.md) (60 min) — Script 8 del pipeline

## Scripts del Pipeline

Esta sesión cubre los scripts de **etiquetado** del pipeline de procesamiento:

| Script | Archivo | Función |
|--------|---------|---------|
| Script 7 | `7_sysmon_seed_event_extractor.py` | Extracción de eventos semilla (EventID 1, 11, 23) |
| Script 8 | `8_sysmon_attack_lifecycle_tracer.py` | Trazado de cadenas de ataque desde eventos semilla |
