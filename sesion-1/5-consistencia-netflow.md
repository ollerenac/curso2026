# Consistencia Estructural NetFlow

**Duración**: 35 minutos

## Contexto

En la sección 3 aprendimos la técnica de **fingerprinting estructural** para validar la consistencia de los datos Sysmon. El resultado fue revelador: 19 patrones estructurales correspondientes a 19 EventIDs, con una correspondencia perfecta 1:1 y una evaluación de **ALTAMENTE CONSISTENTE**.

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

En la sección 3 construimos una función `generate_structure_fingerprint()` que tomaba el EventID y los nombres de campo del XML para generar un hash MD5. Para NetFlow, la técnica es la misma pero la implementación cambia: en lugar de parsear XML para extraer nombres de campo, **hasheamos la estructura del JSON directamente**.

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

:::{admonition} ¿Cómo funciona generate_schema_fingerprint?
:class: dropdown note

Recorre recursivamente el JSON y construye un diccionario que representa solo la *forma* del registro (nombres de campo + tipos, sin valores). Luego serializa ese diccionario con `json.dumps(sort_keys=True)` — el ordenamiento garantiza que dos registros con los mismos campos en distinto orden produzcan el mismo string — y genera un hash MD5.

Reglas para cada tipo de valor:
- `dict` → desciende recursivamente, ordenando las claves
- `list` vacía → `"empty_list"`
- `list` no vacía → `{"list_of": estructura_del_primer_elemento}`
- primitivo (`str`, `int`, `bool`) → devuelve solo el nombre del tipo

El resultado es una tupla `(hash, structure_detail)`. Dos registros con exactamente los mismos campos, tipos y niveles de anidamiento producirán el mismo hash aunque sus valores sean completamente distintos.

Contraste con la versión Sysmon:
```
Sysmon:   EventID + [campo1:present, campo2:null, ...]  →  MD5
NetFlow:  {campo1: {subcampo: "str"}, campo2: "int"}    →  MD5
```
:::

:::{admonition} ¿Cómo funciona classify_structure_variations?
:class: dropdown note

Recibe un `Counter` de `{hash: frecuencia}` y clasifica cada patrón según su porcentaje de aparición:

| Umbral | Clasificación |
|--------|--------------|
| ≥ 50% | `PRIMARY_SCHEMA` |
| ≥ 20% | `SECONDARY_SCHEMA` |
| ≥ 5% | `VARIANT` |
| ≥ 1% | `RARE_VARIANT` |
| < 1% | `OUTLIER` |

Retorna un diccionario `{hash: {classification, count, percentage}}`. Esta clasificación permite distinguir rápidamente los patrones dominantes de los casos excepcionales sin inspeccionar el conteo raw.
:::

:::{admonition} ¿Cómo funciona analyze_field_presence_patterns?
:class: dropdown note

Recorre todos los registros y extrae recursivamente cada ruta de campo en dot-notation. Cuenta cuántas veces aparece cada ruta en el total de registros. El resultado muestra qué campos son universales (100%) vs opcionales (<100%), con más granularidad que el análisis de primer nivel del notebook 4a — aquí se detectan variaciones a cualquier nivel de anidamiento, no solo en el primer nivel.
:::

```
Contraste de fingerprinting:

  Sysmon:   EventID + [campo1:present, campo2:null, ...]  →  MD5
  NetFlow:  {campo1: {subcampo: "str"}, campo2: "int"}    →  MD5
```

## Paso 2: Resultados — 15 patrones estructurales

El fingerprinting de 200,000 registros muestreados produce los siguientes resultados:

```
Unique structure patterns found: 15
Records analyzed:                200,000
Most common pattern frequency:   79,773 records

PATTERN CLASSIFICATION:
   OUTLIER:          8 patterns
   VARIANT:          3 patterns
   SECONDARY_SCHEMA: 2 patterns
   RARE_VARIANT:     2 patterns
```

**¿Qué nos dice este resultado?**

- Existen **15 patrones estructurales únicos** en los 200,000 registros — una variabilidad mucho mayor que los 2 patrones esperados (con y sin `process`).
- Ningún patrón alcanza el 50% de frecuencia, por lo que no hay `PRIMARY_SCHEMA`. Los dos patrones más frecuentes (`SECONDARY_SCHEMA`) concentran el ~72% de los registros.
- Los 8 patrones clasificados como `OUTLIER` representan menos del 1% cada uno — probablemente variantes menores por diferencias de tipo o campos opcionales adicionales.
- A diferencia de Sysmon, donde cada patrón correspondía a un EventID concreto, aquí **no existe ese discriminador natural**. El siguiente paso es inspeccionar cada patrón en detalle para entender qué los diferencia.

## Paso 3: Análisis detallado de patrones estructurales

Para entender qué diferencia a cada patrón estructural, el notebook itera sobre los 10 más frecuentes e inspecciona sus características:

```python
sorted_patterns = structure_counts.most_common()

for i, (structure_hash, count) in enumerate(sorted_patterns[:10], 1):
    classification_info = classifications[structure_hash]

    # Frecuencia y clasificación
    print(f"PATTERN #{i} - {classification_info['classification']}")
    print(f"Frequency: {count:,} records ({classification_info['percentage']:.2f}%)")

    # Campos de primer nivel del registro ejemplo
    example_record = structure_examples[structure_hash]
    top_level_fields = list(example_record.keys())
    print(f"Top-level fields ({len(top_level_fields)}): {', '.join(sorted(top_level_fields))}")

    # Detectar características notables (process, source.process)
    optional_indicators = []
    for field in top_level_fields:
        if field == 'process':
            optional_indicators.append(f"process: {type(example_record[field]).__name__}")
        elif field == 'source' and 'process' in example_record[field]:
            optional_indicators.append("source.process: present")

    # Comparar diferencias estructurales con el patrón #1
    if i > 1:
        primary_fields = set(str(structure_fingerprints[sorted_patterns[0][0]]).split())
        current_fields = set(str(structure_fingerprints[structure_hash]).split())
        missing = primary_fields - current_fields
        extra = current_fields - primary_fields
        if missing or extra:
            print(f"Differences from Pattern #1: -{len(missing)} / +{len(extra)} structural elements")
```

:::{admonition} ¿Qué hace este código?
:class: dropdown note

Para cada uno de los 10 patrones más frecuentes (ordenados de mayor a menor por `structure_counts.most_common()`), el código extrae tres cosas:

1. **Clasificación y frecuencia** — cuántos registros tienen ese patrón estructural y qué categoría le asignó `classify_structure_variations`.
2. **Campos de primer nivel** — cuántos campos tiene el registro ejemplo y cuáles son. Esto permite identificar de inmediato si el patrón incluye o no el campo `process`.
3. **Diferencias vs patrón #1** — compara el string serializado del fingerprint actual contra el del patrón más frecuente. Si hay elementos estructurales presentes en uno pero no en el otro, lo reporta como "missing" o "extra". Es una comparación de strings aproximada, no campo a campo.

`structure_examples` es un diccionario `{hash: primer_registro_con_ese_hash}` construido durante el Step 2 — guarda un registro representativo de cada patrón para poder inspeccionarlo.
:::

Los 15 patrones estructurales en detalle:

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

El Step 4 del notebook usa `analyze_field_presence_patterns` para recorrer los 200,000 registros y contar cuántas veces aparece cada ruta de campo a cualquier nivel de anidamiento:

```python
field_combinations, field_counts = analyze_field_presence_patterns(sample_records)

# Campos condicionales: presentes en menos del 95% de los registros
conditional_fields = [
    (field, count, (count / total_samples) * 100)
    for field, count in field_counts.items()
    if (count / total_samples) * 100 < 95
]
conditional_fields.sort(key=lambda x: x[2])  # ordenar por rareza
```

:::{admonition} ¿Qué diferencia este análisis del de la sección 4?
:class: dropdown note

El notebook 4a analizó solo los **12 campos de primer nivel** (estructura superficial). Este Step 4 recorre recursivamente **todas las rutas anidadas** — `destination.process.args`, `host.os.kernel`, etc. — sobre los 200,000 registros completos. Por eso encuentra 89 rutas únicas en lugar de las 96 del 4a (diferencia de método de sampling: estratificado vs reservoir) y detecta que `destination.bytes` y `destination.packets` son opcionales al 90.1%, algo invisible en el análisis de primer nivel.
:::

El output del Step 4:

```
Field presence analysis:
   • Total unique field paths:   89
   • Unique field combinations:  11

Conditional/Optional fields (present in <95% of records):
   destination.process.*        15,981 (  8.0%)
   source.process.*             82,359 ( 41.2%)
   process.*                    98,340 ( 49.2%)
   destination.bytes           180,198 ( 90.1%)
   destination.packets         180,198 ( 90.1%)

Most common field combinations (top 10):
   Combination with 81 fields:  79,906 records ( 40.0%)
   Combination with 64 fields:  79,773 records ( 39.9%)
   Combination with 81 fields:  15,670 records (  7.8%)
   Combination with 62 fields:  15,397 records (  7.7%)
   Combination with 57 fields:   4,560 records (  2.3%)
   Combination with 79 fields:   2,453 records (  1.2%)
   Combination with 55 fields:     781 records (  0.4%)
   Combination with 60 fields:     701 records (  0.4%)
   Combination with 79 fields:     311 records (  0.2%)
   Combination with 62 fields:     289 records (  0.1%)
```

Los campos se distribuyen en dos categorías:

```
Total de rutas de campo únicas:      89
Combinaciones únicas de campos:      11
```

Los campos se distribuyen en dos categorías:

| Categoría | Cantidad | Presencia | Ejemplos |
|-----------|----------|-----------|----------|
| Siempre presentes | 62 | 100.0% | `agent.*`, `destination.mac`, `network.*`, `source.bytes` |
| Condicionales | 27 | 8–90% | `process.*` (49.2%), `source.process.*` (41.2%), `destination.process.*` (8.0%), `destination.bytes` (90.1%) |

**Detalle de los campos condicionales:**

```
process.*                (9 rutas)    →  98,340 registros (49.2%)
source.process.*         (8 rutas)    →  82,359 registros (41.2%)
destination.process.*    (8 rutas)    →  15,981 registros ( 8.0%)

destination.bytes        (1 ruta)     → 180,198 registros (90.1%)
destination.packets      (1 ruta)     → 180,198 registros (90.1%)
```

La diferencia entre `process` (49.2%) y `source.process` (41.2%) indica que hay un ~8% de registros donde el proceso se identifica a nivel de registro pero no en el subobjeto `source`. Estos son precisamente los registros del **patrón #5** (VARIANT, 7.36%), donde el proceso está asociado al host local pero sin atribución al extremo origen del flujo.

El campo `destination.process` aparece en el 8.0% de los registros — flujos donde Packetbeat también pudo identificar el proceso receptor en el host destino. Cada grupo de campos `destination.process.*` incluye 8 subrutas (`args`, `start`, `name`, `working_directory`, `pid`, `executable`, `ppid`) que siempre aparecen o desaparecen en bloque — nunca de forma parcial.

**Hallazgo clave:** Los 62 campos siempre presentes incluyen toda la infraestructura de metadatos (`agent.*`, `elastic_agent.*`, `ecs.*`, `data_stream.*`) y la información del host (`host.hostname`, `host.os.*`). Notablemente, `destination.bytes` y `destination.packets` solo aparecen en el 90.1% de los registros — los flujos donde no se midió el tráfico bidireccional completo quedan sin estos valores. El **núcleo de la información de red está presente en la gran mayoría de los registros**, pero no es absolutamente universal como en el dominio Sysmon.

## Paso 5: Evaluación de consistencia

El reporte de consistencia del notebook `5a` concluye con la evaluación:

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

NetFlow **carece de discriminador de tipo**. No existe un equivalente a EventID. La variación proviene de **campos opcionales** (`process`, `source.process`, `destination.process`) cuya presencia depende de factores operativos (si el host está monitorizado, si Packetbeat pudo correlacionar el flujo con un proceso). Los 15 patrones reflejan las combinaciones posibles de estos campos opcionales.

En resumen: Sysmon tiene variación **determinista** (predecible por EventID), mientras que NetFlow tiene variación **estocástica** (dependiente de condiciones operativas). Esta distinción tiene consecuencias directas para el diseño de los conversores CSV en la sesión 2.

## Implicaciones para el conversor CSV

La estrategia de conversión JSONL a CSV para NetFlow debe contemplar las tres categorías de campos:

| Categoría | Cantidad | Estrategia de extracción |
|-----------|----------|--------------------------|
| Siempre presentes | 62 campos | Extracción estándar directa |
| Condicionales | 27 campos | Valores por defecto (`None`/vacío) cuando ausentes |

A diferencia del conversor Sysmon — que usa un esquema fijo por EventID — el conversor NetFlow debe emplear un **esquema unificado** con manejo de nulos para los campos opcionales.

## Conclusiones e implicaciones

El análisis de consistencia estructural de NetFlow revela un panorama cualitativamente distinto al de Sysmon:

1. **Menos patrones, menor consistencia (15 vs 19)**: Puede parecer contraintuitivo que 15 patrones produzcan una evaluación de MODERADAMENTE CONSISTENTE mientras que 19 patrones producen ALTAMENTE CONSISTENTE. La diferencia está en la **naturaleza** de la variación: en Sysmon, cada patrón corresponde a un EventID conocido y predecible; en NetFlow, los 15 patrones reflejan combinaciones impredecibles de campos opcionales.

2. **Un solo eje de variación**: Toda la diversidad estructural se reduce a una pregunta binaria: ¿se pudo atribuir el flujo de red a un proceso? Cuando sí, aparecen `process` y `source.process`; cuando no, ambos se omiten. Esta atribución depende de factores operativos (si Packetbeat monitoriza el host), no del tipo de evento.

3. **Núcleo estable de 62 campos**: De las 89 rutas de campo, 62 están presentes en el 100% de los registros. La mayor parte de la infraestructura de red está siempre completa, aunque `destination.bytes` y `destination.packets` solo aparecen en el 90.1% de los flujos — solo la atribución a proceso y la medición completa del destino son variables. Esto contrasta con Sysmon, donde solo 2 campos (`UtcTime`, `RuleName`) son universales.

4. **Variación determinista vs estocástica**: En Sysmon, conocer el EventID permite predecir exactamente qué campos contendrá el registro. En NetFlow, no existe esa predicción — la presencia de `process` depende de si el host estaba monitorizado en el momento del flujo. Esta distinción tiene consecuencias directas para el diseño de los conversores CSV.

**Implicación para el preprocesamiento**: El conversor NetFlow (Script 3) debe implementar un **esquema unificado** donde las 89 rutas se extraen con `get_nested_value()`, usando valores por defecto (`None`) para los campos ausentes. En contraste, el conversor Sysmon (Script 2) usa un esquema fijo por EventID con el diccionario `fields_per_eventid`.

## Actividad Práctica

### Ejercicio: Análisis Comparativo de Consistencia

Responde las siguientes preguntas basándote en el análisis de consistencia:

1. **¿Por qué Sysmon logra una evaluación "ALTAMENTE CONSISTENTE" mientras que NetFlow es solo "MODERADAMENTE CONSISTENTE", a pesar de tener menos patrones (15 vs 19)?** Explica el papel del discriminador de tipo (EventID) en la consistencia estructural.

2. **¿Qué nos dice la presencia de `process` en el 64% de los registros sobre la infraestructura de monitorización?** Considera: si un flujo va de un host externo a un servidor monitorizado, ¿aparecería `process`, `source.process`, `destination.process`, o ninguno?

3. **Si quisiéramos añadir un campo discriminador a NetFlow (equivalente a EventID), ¿cuál sería el candidato más natural?** Pista: piensa en la presencia/ausencia de `process` como una variable binaria. ¿Cuántos "tipos" definirías y qué significaría cada uno?

4. **Los patrones #1 y #3 comparten las mismas características visibles** (ambos tienen `process` y `source.process`), pero el fingerprinting los distingue como patrones diferentes. **Diseña un test** para verificar que esta diferencia es real y no un artefacto del hashing. ¿Qué campos o subestructuras examinarías?

### Resultado esperado

Al finalizar esta sección, deberías comprender:

- Cómo adaptar la técnica de fingerprinting de XML plano (Sysmon) a JSON anidado (NetFlow).
- Que los 15 patrones de NetFlow reflejan variación **estocástica** (campos opcionales) frente a la variación **determinista** de Sysmon (EventIDs).
- La distribución de campos: 64 siempre presentes, 17 condicionales, 8 raros.
- Por qué esta consistencia moderada requiere un conversor con esquema unificado y manejo de nulos.

---

En la siguiente sección cerramos la Sesión 1 con una síntesis de todo lo aprendido y una vista previa de cómo estos hallazgos alimentan las sesiones siguientes.
