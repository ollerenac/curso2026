# Consistencia Estructural NetFlow

**Duración**: 35 minutos

## Contexto

En la sección 4 aprendimos la técnica de **fingerprinting estructural** para validar la consistencia de los datos Sysmon. El resultado fue revelador: 19 patrones estructurales correspondientes a 19 EventIDs, con una correspondencia perfecta 1:1 y una evaluación de **ALTAMENTE CONSISTENTE**.

Ahora aplicamos la **misma técnica** al dominio NetFlow. En la sección anterior descubrimos que los datos NetFlow son JSON anidado puro con 96 rutas de campo y un campo `process` opcional (49.0%). La pregunta es: **¿qué tan uniforme es esa estructura a lo largo de los 200,000 registros analizados?**

La respuesta, como veremos, es diferente a la de Sysmon — y las razones de esa diferencia revelan aspectos fundamentales sobre la naturaleza de cada dominio de telemetría.

```{note}
El código de esta sección se puede ejecutar paso a paso en el notebook `5a-structure-consistency-analyzer.ipynb`, que contiene el análisis completo de consistencia estructural para NetFlow con celdas interactivas y resultados detallados.
```

```{admonition} Antes de continuar — haz una predicción
:class: note

Antes de ver los resultados, piensa:

1. NetFlow no tiene EventID. ¿Esperarías **más** o **menos** patrones estructurales que los 19 de Sysmon?
2. Sin un discriminador de tipo, ¿sería la consistencia **mayor** o **menor**?
3. ¿Qué campo crees que causa la mayor variación?

Anota tus predicciones y compáralas con los resultados.
```

## Paso 1: Aplicación del fingerprinting a NetFlow

En la sección 4 construimos una función `generate_structure_fingerprint()` que tomaba el EventID y los nombres de campo del XML para generar un hash MD5. Para NetFlow, la técnica es la misma pero la implementación cambia: en lugar de parsear XML para extraer nombres de campo, **hasheamos la estructura del JSON directamente**.

La función adaptada para NetFlow recorre recursivamente el diccionario JSON, extrayendo la estructura completa (nombres de campo, tipos y anidamiento):

```python
import hashlib
import json

def generate_schema_fingerprint(record, max_depth=10):
    """Genera un fingerprint estructural para un registro JSON NetFlow."""
    def extract_structure(obj, current_depth=0):
        if current_depth >= max_depth:
            return "max_depth_reached"

        if isinstance(obj, dict):
            # Ordenar claves para hash consistente
            structure = {}
            for key in sorted(obj.keys()):
                structure[key] = extract_structure(obj[key], current_depth + 1)
            return structure
        elif isinstance(obj, list):
            if not obj:
                return "empty_list"
            # Para listas, analizar estructura del primer elemento
            return {"list_of": extract_structure(obj[0], current_depth + 1)}
        else:
            # Para primitivos, registrar el tipo
            return type(obj).__name__

    # Extraer estructura completa
    structure_detail = extract_structure(record)

    # Crear representación estable para hashing
    structure_str = json.dumps(structure_detail, sort_keys=True)
    structure_hash = hashlib.md5(structure_str.encode('utf-8')).hexdigest()

    return structure_hash, structure_detail
```

**¿Cómo funciona?**

1. Recorre recursivamente el diccionario JSON, descendiendo por cada clave.
2. Para cada campo, registra su **tipo** (`str`, `int`, `bool`, `dict`, `list`).
3. Las listas se representan por la estructura de su primer elemento.
4. Serializa la estructura completa como JSON ordenado y genera un hash MD5.

El resultado es un identificador único para cada *forma* del JSON. Dos registros con exactamente los mismos campos, tipos y niveles de anidamiento producirán el mismo fingerprint, independientemente de los valores concretos.

**Diferencias clave con la versión Sysmon:**

1. **Sin EventID en el hash**: NetFlow no tiene un discriminador de tipo equivalente a EventID. El hash se genera exclusivamente a partir de la estructura JSON.
2. **Recursión multinivel**: En Sysmon, los campos del XML eran planos (un solo nivel). Aquí la función desciende recursivamente a través de diccionarios anidados (`source.process.args`, `host.os.kernel`, etc.).
3. **Tipado de valores**: Además de registrar la presencia/ausencia de campos, esta versión captura el **tipo** de cada valor (`str`, `int`, `bool`, `dict`, `list`), lo que detecta variaciones más sutiles.

```
Contraste de fingerprinting:

  Sysmon:   EventID + [campo1:present, campo2:null, ...]  →  MD5
  NetFlow:  {campo1: {subcampo: "str"}, campo2: "int"}    →  MD5
```

## Paso 2: Resultados — 15 patrones estructurales

El fingerprinting de 200,000 registros muestreados produce los siguientes resultados:

```
Patrones estructurales únicos:   15
Registros analizados:            200,000
Ratio de diversidad estructural: 0.007%
Patrón más frecuente:            79,773 registros (39.89%)
```

A diferencia de Sysmon, donde cada patrón correspondía a un EventID, aquí no existe ese discriminador natural. Los 15 patrones se clasifican por frecuencia:

| # | Clasificación | Registros | % | Campos 1er nivel | Características |
|---|--------------|-----------|---|-------------------|-----------------|
| 1 | SECONDARY_SCHEMA | 79,773 | 39.89% | 11 | Sin `process` |
| 2 | SECONDARY_SCHEMA | 64,313 | 32.16% | 12 | `process` + `source.process` |
| 3 | VARIANT | 15,593 | 7.80% | 12 | `process` + `source.process` (variante) |
| 4 | VARIANT | 15,397 | 7.70% | 11 | Sin `process` (variante) |
| 5 | VARIANT | 14,727 | 7.36% | 12 | `process` sin `source.process` |
| 6 | RARE_VARIANT | 4,560 | 2.28% | 11 | Variante menor sin `process` |
| 7 | RARE_VARIANT | 2,196 | 1.10% | 12 | `process` + `source.process` (variante) |
| 8 | OUTLIER | 943 | 0.47% | 12 | Variante con `process` |
| 9 | OUTLIER | 781 | 0.39% | 11 | Variante menor |
| 10 | OUTLIER | 701 | 0.35% | 11 | Variante menor |
| 11-15 | OUTLIER | <500 | <0.25% | variable | Variantes residuales |

**Clasificación por tipo:**

```
SECONDARY_SCHEMA:   2 patrones  (72.05% de los registros)
VARIANT:            3 patrones  (22.86% de los registros)
RARE_VARIANT:       2 patrones  ( 3.38% de los registros)
OUTLIER:            8 patrones  ( 1.71% de los registros)
PRIMARY_SCHEMA:     0 patrones  (ningún patrón supera el 50%)
```

**Observación importante:** Ningún patrón alcanza el 50% de frecuencia necesario para clasificarse como PRIMARY_SCHEMA. Los dos patrones SECONDARY_SCHEMA (~40% y ~32%) concentran el 72% de los registros, mientras que tres patrones VARIANT adicionales (~8%, ~8%, ~7%) suman el 23%. La distribución es más dispersa que en Sysmon, donde los patrones más frecuentes superaban el 30% individualmente.

## Paso 3: El campo `process` como eje de variación

El análisis detallado de los patrones revela que el **eje principal de variación** es la presencia o ausencia de campos relacionados con proceso:

**Patrón #1** (39.89%): No incluye `process`. Son flujos donde no fue posible correlacionar la actividad de red con un proceso del sistema operativo — típicamente tráfico externo, de dispositivos no monitorizados, o flujos TCP ya establecidos cuando inició Packetbeat.

**Patrón #2** (32.16%): Incluye `process` y `source.process`. Registros donde Packetbeat identificó el proceso en el host local y lo asoció al extremo origen del flujo.

**Patrón #3** (7.80%): Incluye `process` y `source.process`, pero con una variante estructural en el campo `args` (lista vacía en lugar de lista con elementos), que produce un fingerprint diferente al patrón #2.

**Patrón #4** (7.70%): Sin `process`, variante estructural menor respecto al patrón #1.

**Patrón #5** (7.36%): Incluye `process` pero **sin** `source.process`. Son flujos donde se identificó el proceso a nivel de registro, pero Packetbeat no pudo asociarlo al subobjeto `source` — típicamente cuando el proceso está vinculado al destino y no al origen.

```
Eje de variación principal:

  Patrón #1 (39.89%) ─── process: ✗   source.process: ✗
  Patrón #2 (32.16%) ─── process: ✓   source.process: ✓
  Patrón #3 ( 7.80%) ─── process: ✓   source.process: ✓  (variante args vacío)
  Patrón #4 ( 7.70%) ─── process: ✗   source.process: ✗  (variante)
  Patrón #5 ( 7.36%) ─── process: ✓   source.process: ✗
                         ────────────────────────────────────
                    SECONDARY + VARIANT:  94.91%
```

La distinción principal sigue siendo **¿se pudo atribuir el flujo a un proceso?** Cuando sí, aparece `process`; cuando no, se omite. Sin embargo, a diferencia de lo que podría esperarse, la presencia de `process` no garantiza la presencia de `source.process` — el patrón #5 demuestra que ~7% de los flujos tienen proceso a nivel de registro pero sin atribución al subobjeto origen. La atribución de proceso solo es posible para flujos que se originan o terminan en **hosts monitorizados** con Packetbeat instalado — aproximadamente el 49% de todos los flujos en la muestra.

## Paso 4: Co-ocurrencia de campos

El análisis de co-ocurrencia de campos revela la anatomía completa de las 89 rutas de campo únicas:

```
Total de rutas de campo únicas:      89
Combinaciones únicas de campos:      11
```

Los campos se distribuyen en tres categorías claras:

| Categoría | Cantidad | Presencia | Ejemplos |
|-----------|----------|-----------|----------|
| Siempre presentes | 62 | 100.0% | `agent.*`, `destination.mac`, `network.*`, `source.bytes` |
| Condicionales | 27 | 8-90% | `process.*` (49.2%), `source.process.*` (41.2%), `destination.process.*` (8.0%), `destination.bytes` (90.1%) |
| Raros | 0 | — | — |

**Detalle de los campos condicionales:**

```
process.*                (9 rutas)    →  98,340 registros (49.2%)
source.process.*         (8 rutas)    →  82,359 registros (41.2%)
destination.process.*    (8 rutas)    →  15,981 registros ( 8.0%)

destination.bytes        (1 ruta)     → 180,198 registros (90.1%)
destination.packets      (1 ruta)     → 180,198 registros (90.1%)
```

La diferencia entre `process` (49.2%) y `source.process` (41.2%) indica que hay un ~8% de registros donde el proceso se identifica a nivel de registro pero no en el subobjeto `source`. Estos son precisamente los registros del **patrón #5** (VARIANT, 7.36%), donde el proceso está asociado al host local pero sin atribución al extremo origen del flujo.

El campo `destination.process` aparece en el 8.0% de los registros — flujos donde Packetbeat también pudo identificar el proceso receptor en el host destino. En el run original este porcentaje era solo 2.8%; el incremento en `run-01` refleja diferencias en la naturaleza del tráfico APT capturado. Cada grupo de campos `destination.process.*` incluye 8 subrutas (`args`, `start`, `name`, `working_directory`, `pid`, `executable`, `ppid`) que siempre aparecen o desaparecen en bloque — nunca de forma parcial.

**Hallazgo clave:** Los 62 campos siempre presentes incluyen toda la infraestructura de metadatos (`agent.*`, `elastic_agent.*`, `ecs.*`, `data_stream.*`) y la información del host (`host.hostname`, `host.os.*`). Notablemente, `destination.bytes` y `destination.packets` solo aparecen en el 90.1% de los registros — los flujos donde no se midió el tráfico bidireccional completo quedan sin estos valores. El **núcleo de la información de red está presente en la gran mayoría de los registros**, pero no es absolutamente universal como en el dominio Sysmon.

## Paso 5: Evaluación de consistencia

El reporte de consistencia del notebook 3b concluye con la evaluación:

```
MÉTRICAS DE CONSISTENCIA:
   Patrones estructurales únicos:       15
   Patrones Primary/Secondary:           2
   Ratio de diversidad estructural:      0.007%

ANÁLISIS DE COBERTURA:
   Top 3 patrones cubren:   79.8% de los datos
   Top 5 patrones cubren:   94.9% de los datos
   Top 10 patrones cubren:  99.5% de los datos

EVALUACIÓN GENERAL: MODERADAMENTE CONSISTENTE
```

### Contraste con Sysmon

La comparación directa entre ambos dominios revela por qué las evaluaciones difieren:

| Métrica | Sysmon | NetFlow |
|---------|--------|---------|
| Patrones únicos | 19 | 15 |
| Consistencia intra-tipo | 100% (cada EventID = 1 patrón) | N/A (sin tipos) |
| Cobertura top-3 | ~77.8% | ~79.8% |
| Cobertura top-5 | ~93.9% | ~94.9% |
| Campos siempre presentes | 2 (de 74) | 62 (de 89) |
| Evaluación | ALTAMENTE CONSISTENTE | MODERADAMENTE CONSISTENTE |

**¿Por qué Sysmon es "altamente consistente" con más patrones (19 vs 15)?**

La respuesta está en el **discriminador de tipo**. Sysmon tiene el campo `EventID` que actúa como discriminador natural: cada EventID produce siempre la misma estructura de campos, sin excepciones. Hay 19 patrones porque hay 19 EventIDs distintos, y la correspondencia es perfecta 1:1.

NetFlow **carece de discriminador de tipo**. No existe un equivalente a EventID. La variación proviene de **campos opcionales** (`process`, `source.process`, `destination.process`) cuya presencia depende de factores operativos (si el host está monitorizado, si Packetbeat pudo correlacionar el flujo con un proceso). Los 14 patrones reflejan las combinaciones posibles de estos campos opcionales.

En resumen: Sysmon tiene variación **determinista** (predecible por EventID), mientras que NetFlow tiene variación **estocástica** (dependiente de condiciones operativas). Esta distinción tiene consecuencias directas para el diseño de los conversores CSV en la sesión 2.

## Implicaciones para el conversor CSV

La estrategia de conversión JSONL a CSV para NetFlow debe contemplar las tres categorías de campos:

| Categoría | Cantidad | Estrategia de extracción |
|-----------|----------|--------------------------|
| Siempre presentes | 62 campos | Extracción estándar directa |
| Condicionales | 27 campos | Valores por defecto (`None`/vacío) cuando ausentes |
| Raros | 0 campos | — |

A diferencia del conversor Sysmon — que usa un esquema fijo por EventID — el conversor NetFlow debe emplear un **esquema unificado** con manejo de nulos para los campos opcionales. Esto se implementa con la función `get_nested_value()` de la sección anterior, que devuelve un valor por defecto cuando la ruta no existe en el registro.

## Conclusiones e implicaciones

El análisis de consistencia estructural de NetFlow revela un panorama cualitativamente distinto al de Sysmon:

1. **Menos patrones, menor consistencia (15 vs 19)**: Puede parecer contraintuitivo que 14 patrones produzcan una evaluación de MODERADAMENTE CONSISTENTE mientras que 19 patrones producen ALTAMENTE CONSISTENTE. La diferencia está en la **naturaleza** de la variación: en Sysmon, cada patrón corresponde a un EventID conocido y predecible; en NetFlow, los 14 patrones reflejan combinaciones impredecibles de campos opcionales.

2. **Un solo eje de variación**: Toda la diversidad estructural se reduce a una pregunta binaria: ¿se pudo atribuir el flujo de red a un proceso? Cuando sí, aparecen `process` y `source.process`; cuando no, ambos se omiten. Esta atribución depende de factores operativos (si Packetbeat monitoriza el host), no del tipo de evento.

3. **Núcleo estable de 62 campos**: De las 89 rutas de campo, 62 están presentes en el 100% de los registros. La mayor parte de la infraestructura de red está siempre completa, aunque `destination.bytes` y `destination.packets` solo aparecen en el 90.1% de los flujos — solo la atribución a proceso y la medición completa del destino son variables. Esto contrasta con Sysmon, donde solo 2 campos (`UtcTime`, `RuleName`) son universales.

4. **Variación determinista vs estocástica**: En Sysmon, conocer el EventID permite predecir exactamente qué campos contendrá el registro. En NetFlow, no existe esa predicción — la presencia de `process` depende de si el host estaba monitorizado en el momento del flujo. Esta distinción tiene consecuencias directas para el diseño de los conversores CSV.

**Implicación para el preprocesamiento**: El conversor NetFlow (Script 3) debe implementar un **esquema unificado** donde las 89 rutas se extraen con `get_nested_value()`, usando valores por defecto (`None`) para los campos ausentes. En contraste, el conversor Sysmon (Script 2) usa un esquema fijo por EventID con el diccionario `fields_per_eventid`.

## Actividad Práctica

### Ejercicio: Análisis Comparativo de Consistencia

Responde las siguientes preguntas basándote en el análisis de consistencia:

1. **¿Por qué Sysmon logra una evaluación "ALTAMENTE CONSISTENTE" mientras que NetFlow es solo "MODERADAMENTE CONSISTENTE", a pesar de tener menos patrones (14 vs 19)?** Explica el papel del discriminador de tipo (EventID) en la consistencia estructural.

2. **¿Qué nos dice la presencia de `process` en el 64% de los registros sobre la infraestructura de monitorización?** Considera: si un flujo va de un host externo a un servidor monitorizado, ¿aparecería `process`, `source.process`, `destination.process`, o ninguno?

3. **Si quisiéramos añadir un campo discriminador a NetFlow (equivalente a EventID), ¿cuál sería el candidato más natural?** Pista: piensa en la presencia/ausencia de `process` como una variable binaria. ¿Cuántos "tipos" definirías y qué significaría cada uno?

4. **Los patrones #1 y #3 comparten las mismas características visibles** (ambos tienen `process` y `source.process`), pero el fingerprinting los distingue como patrones diferentes. **Diseña un test** para verificar que esta diferencia es real y no un artefacto del hashing. ¿Qué campos o subestructuras examinarías?

### Resultado esperado

Al finalizar esta sección, deberías comprender:

- Cómo adaptar la técnica de fingerprinting de XML plano (Sysmon) a JSON anidado (NetFlow).
- Que los 14 patrones de NetFlow reflejan variación **estocástica** (campos opcionales) frente a la variación **determinista** de Sysmon (EventIDs).
- La distribución de campos: 64 siempre presentes, 17 condicionales, 8 raros.
- Por qué esta consistencia moderada requiere un conversor con esquema unificado y manejo de nulos.

---

En la siguiente sección cerramos la Sesión 1 con una síntesis de todo lo aprendido y una vista previa de cómo estos hallazgos alimentan las sesiones siguientes.
