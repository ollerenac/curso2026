# Consistencia Estructural NetFlow

**Duración**: 35 minutos

## Contexto

En la sección 4 aprendimos la técnica de **fingerprinting estructural** para validar la consistencia de los datos Sysmon. El resultado fue revelador: 19 patrones estructurales correspondientes a 19 EventIDs, con una correspondencia perfecta 1:1 y una evaluación de **ALTAMENTE CONSISTENTE**.

Ahora aplicamos la **misma técnica** al dominio NetFlow. En la sección anterior descubrimos que los datos NetFlow son JSON anidado puro con 87 rutas de campo y un campo `process` opcional (62.8%). La pregunta es: **¿qué tan uniforme es esa estructura a lo largo de los 200,000 registros analizados?**

La respuesta, como veremos, es diferente a la de Sysmon — y las razones de esa diferencia revelan aspectos fundamentales sobre la naturaleza de cada dominio de telemetría.

```{note}
El código de esta sección se puede ejecutar paso a paso en el notebook `3b-structure-consistency-analyzer.ipynb`, que contiene el análisis completo de consistencia estructural para NetFlow con celdas interactivas y resultados detallados.
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

## Paso 2: Resultados — 14 patrones estructurales

El fingerprinting de 200,000 registros muestreados produce los siguientes resultados:

```
Patrones estructurales únicos:   14
Registros analizados:            200,000
Ratio de diversidad estructural: 0.007%
Patrón más frecuente:            67,260 registros (33.63%)
```

A diferencia de Sysmon, donde cada patrón correspondía a un EventID, aquí no existe ese discriminador natural. Los 14 patrones se clasifican por frecuencia:

| # | Clasificación | Registros | % | Campos 1er nivel | Características |
|---|--------------|-----------|---|-------------------|-----------------|
| 1 | SECONDARY_SCHEMA | 67,260 | 33.63% | 12 | `process` + `source.process` |
| 2 | SECONDARY_SCHEMA | 67,235 | 33.62% | 11 | Sin `process` |
| 3 | SECONDARY_SCHEMA | 54,406 | 27.20% | 12 | `process` + `source.process` (variante) |
| 4 | RARE_VARIANT | 5,253 | 2.63% | 12 | `process` sin `source.process` |
| 5 | RARE_VARIANT | 3,037 | 1.52% | 11 | Sin `process` (variante) |
| 6 | OUTLIER | 708 | 0.35% | 11 | Variante menor |
| 7 | OUTLIER | 583 | 0.29% | 12 | Variante con `process` |
| 8 | OUTLIER | 549 | 0.27% | 11 | Variante menor |
| 9 | OUTLIER | 323 | 0.16% | 11 | Variante menor |
| 10 | OUTLIER | 294 | 0.15% | 12 | Variante con `process` |
| 11-14 | OUTLIER | <300 | <0.15% | variable | Variantes residuales |

**Clasificación por tipo:**

```
SECONDARY_SCHEMA:   3 patrones  (94.45% de los registros)
RARE_VARIANT:       2 patrones  ( 4.15% de los registros)
OUTLIER:            9 patrones  ( 1.40% de los registros)
PRIMARY_SCHEMA:     0 patrones  (ningún patrón supera el 50%)
```

**Observación importante:** Ningún patrón alcanza el 50% de frecuencia necesario para clasificarse como PRIMARY_SCHEMA. Los tres patrones principales (SECONDARY_SCHEMA) se reparten los registros de forma relativamente equilibrada (~34%, ~34%, ~27%), lo que significa que no hay una estructura "dominante" sino tres variantes mayoritarias.

## Paso 3: El campo `process` como eje de variación

El análisis detallado de los patrones revela que el **eje principal de variación** es la presencia o ausencia de campos relacionados con proceso:

**Patrón #1** (33.63%): Incluye `process` y `source.process`. Estos registros corresponden a flujos de red donde Packetbeat pudo identificar tanto el proceso del sistema local como el proceso en el extremo origen del flujo.

**Patrón #2** (33.62%): No incluye `process`. Estos son flujos donde no fue posible correlacionar la actividad de red con un proceso del sistema operativo — típicamente tráfico externo o de dispositivos no monitorizados.

**Patrón #3** (27.20%): Incluye `process` y `source.process`, pero con una variante estructural menor respecto al patrón #1 (un elemento adicional en la estructura del JSON).

```
Eje de variación principal:

  Patrón #1 (33.63%) ─── process: ✓   source.process: ✓
  Patrón #2 (33.62%) ─── process: ✗   source.process: ✗
  Patrón #3 (27.20%) ─── process: ✓   source.process: ✓ (variante)
                         ─────────────────────────────────
                                   Total: 94.45%
```

La distinción fundamental es binaria: **¿se pudo atribuir el flujo a un proceso?** Cuando sí, aparecen tanto `process` como `source.process`; cuando no, ambos se omiten. La atribución de proceso solo es posible para flujos que se originan o terminan en **hosts monitorizados** con Packetbeat instalado — aproximadamente el 64% de todos los flujos en la muestra.

## Paso 4: Co-ocurrencia de campos

El análisis de co-ocurrencia de campos revela la anatomía completa de las 89 rutas de campo únicas:

```
Total de rutas de campo únicas:      89
Combinaciones únicas de campos:      11
```

Los campos se distribuyen en tres categorías claras:

| Categoría | Cantidad | Presencia | Ejemplos |
|-----------|----------|-----------|----------|
| Siempre presentes | 64 | 100.0% | `agent.*`, `destination.mac`, `network.*`, `source.bytes` |
| Condicionales | 17 | 61-64% | `process.*` (64.0%), `source.process.*` (61.2%) |
| Raros | 8 | 2.8% | `destination.process.*` |

**Detalle de los campos condicionales:**

```
process.*                (9 rutas)    → 128,035 registros (64.0%)
source.process.*         (8 rutas)    → 122,460 registros (61.2%)

destination.process.*    (8 rutas)    →   5,575 registros ( 2.8%)
```

La diferencia entre `process` (64.0%) y `source.process` (61.2%) indica que hay un 2.8% de registros donde el proceso se identifica a nivel de registro pero no en el subobjeto `source`. Estos son precisamente los registros del **patrón #4** (RARE_VARIANT, 2.63%), donde el proceso está asociado al destino y no al origen del flujo.

El campo `destination.process` aparece en solo el 2.8% de los registros — estos son flujos donde Packetbeat también pudo identificar el proceso receptor en el host destino. Cada grupo de campos `destination.process.*` incluye 8 subrutas (`args`, `start`, `name`, `working_directory`, `pid`, `executable`, `ppid`) que siempre aparecen o desaparecen en bloque — nunca de forma parcial.

**Hallazgo clave:** Los 64 campos siempre presentes incluyen toda la infraestructura de metadatos (`agent.*`, `elastic_agent.*`, `ecs.*`, `data_stream.*`), las métricas de red (`source.bytes`, `source.packets`, `destination.mac`, `network.*`), y la información del host (`host.hostname`, `host.os.*`). Esto significa que el **núcleo de la información de red está siempre completo** — solo la atribución a proceso es variable.

## Paso 5: Evaluación de consistencia

El reporte de consistencia del notebook 3b concluye con la evaluación:

```
MÉTRICAS DE CONSISTENCIA:
   Patrones estructurales únicos:       14
   Patrones Primary/Secondary:           3
   Ratio de diversidad estructural:      0.007%

ANÁLISIS DE COBERTURA:
   Top 3 patrones cubren:   94.5% de los datos
   Top 5 patrones cubren:   98.6% de los datos
   Top 10 patrones cubren:  99.8% de los datos

EVALUACIÓN GENERAL: MODERADAMENTE CONSISTENTE
```

### Contraste con Sysmon

La comparación directa entre ambos dominios revela por qué las evaluaciones difieren:

| Métrica | Sysmon | NetFlow |
|---------|--------|---------|
| Patrones únicos | 19 | 14 |
| Consistencia intra-tipo | 100% (cada EventID = 1 patrón) | N/A (sin tipos) |
| Cobertura top-3 | ~77.8% | ~94.5% |
| Cobertura top-5 | ~93.9% | ~98.6% |
| Campos siempre presentes | 2 (de 74) | 64 (de 89) |
| Evaluación | ALTAMENTE CONSISTENTE | MODERADAMENTE CONSISTENTE |

**¿Por qué Sysmon es "altamente consistente" con más patrones (19 vs 14)?**

La respuesta está en el **discriminador de tipo**. Sysmon tiene el campo `EventID` que actúa como discriminador natural: cada EventID produce siempre la misma estructura de campos, sin excepciones. Hay 19 patrones porque hay 19 EventIDs distintos, y la correspondencia es perfecta 1:1.

NetFlow **carece de discriminador de tipo**. No existe un equivalente a EventID. La variación proviene de **campos opcionales** (`process`, `source.process`, `destination.process`) cuya presencia depende de factores operativos (si el host está monitorizado, si Packetbeat pudo correlacionar el flujo con un proceso). Los 14 patrones reflejan las combinaciones posibles de estos campos opcionales.

En resumen: Sysmon tiene variación **determinista** (predecible por EventID), mientras que NetFlow tiene variación **estocástica** (dependiente de condiciones operativas). Esta distinción tiene consecuencias directas para el diseño de los conversores CSV en la sesión 2.

## Implicaciones para el conversor CSV

La estrategia de conversión JSONL a CSV para NetFlow debe contemplar las tres categorías de campos:

| Categoría | Cantidad | Estrategia de extracción |
|-----------|----------|--------------------------|
| Siempre presentes | 64 campos | Extracción estándar directa |
| Condicionales | 17 campos | Valores por defecto (`None`/vacío) cuando ausentes |
| Raros | 8 campos | Incluidos en el CSV pero frecuentemente vacíos |

A diferencia del conversor Sysmon — que usa un esquema fijo por EventID — el conversor NetFlow debe emplear un **esquema unificado** con manejo de nulos para los campos opcionales. Esto se implementa con la función `get_nested_value()` de la sección anterior, que devuelve un valor por defecto cuando la ruta no existe en el registro.

## Conclusiones e implicaciones

El análisis de consistencia estructural de NetFlow revela un panorama cualitativamente distinto al de Sysmon:

1. **Menos patrones, menor consistencia (14 vs 19)**: Puede parecer contraintuitivo que 14 patrones produzcan una evaluación de MODERADAMENTE CONSISTENTE mientras que 19 patrones producen ALTAMENTE CONSISTENTE. La diferencia está en la **naturaleza** de la variación: en Sysmon, cada patrón corresponde a un EventID conocido y predecible; en NetFlow, los 14 patrones reflejan combinaciones impredecibles de campos opcionales.

2. **Un solo eje de variación**: Toda la diversidad estructural se reduce a una pregunta binaria: ¿se pudo atribuir el flujo de red a un proceso? Cuando sí, aparecen `process` y `source.process`; cuando no, ambos se omiten. Esta atribución depende de factores operativos (si Packetbeat monitoriza el host), no del tipo de evento.

3. **Núcleo estable de 64 campos**: De las 89 rutas de campo, 64 están presentes en el 100% de los registros. Toda la infraestructura de red (`source.*`, `destination.*`, `network.*`) está siempre completa — solo la atribución a proceso es variable. Esto contrasta con Sysmon, donde solo 2 campos (`UtcTime`, `RuleName`) son universales.

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
