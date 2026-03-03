# Análisis de Consistencia Estructural

**Duración**: 45 minutos

## Contexto: ¿Por qué validar la consistencia?

En la sección anterior descubrimos que los archivos JSONL contienen eventos Sysmon como XML incrustado, y que cada EventID tiene un esquema de campos diferente. Exploramos un solo registro en detalle y analizamos una muestra de 200,000 registros para obtener distribuciones de EventIDs y hosts.

Pero antes de construir un conversor JSONL → CSV, necesitamos responder una pregunta crítica: **¿todos los registros del mismo EventID tienen exactamente la misma estructura?**

Si la respuesta es sí, podemos diseñar un esquema fijo por EventID. Si la respuesta es no, necesitamos manejar variaciones — campos que a veces están presentes y a veces no, o campos que cambian de nombre entre registros.

```{tip}
El código de esta sección se puede ejecutar paso a paso en el notebook `2b-structure-consistency-analyzer.ipynb`, que contiene el análisis completo con celdas interactivas y resultados detallados.
```

## Paso 1: La técnica de fingerprinting estructural

Para comparar la estructura de 200,000 registros de forma eficiente, no podemos comparar cada registro con cada otro — eso sería O(n²). En su lugar, generamos una **huella digital (fingerprint)** para cada registro basada en su estructura:

```python
import hashlib

def generate_structure_fingerprint(event_id, fields_dict):
    """Genera un hash MD5 que identifica la estructura de un registro."""
    structure_elements = [str(event_id)]

    if fields_dict:
        for field_name in sorted(fields_dict.keys()):
            field_value = fields_dict[field_name]
            field_type = "present" if field_value is not None else "null"
            structure_elements.append(f"{field_name}:{field_type}")

    structure_string = "|".join(structure_elements)
    return hashlib.md5(structure_string.encode()).hexdigest()
```

**¿Cómo funciona?**

1. Toma el EventID y los nombres de campos del registro (ordenados alfabéticamente).
2. Para cada campo, registra si el valor está **presente** o es **null**.
3. Concatena todo en un string y genera un hash MD5.

El resultado es un identificador único para cada *tipo de estructura*. Dos registros con exactamente los mismos campos (presentes o null) producirán el mismo fingerprint, independientemente de los valores de los campos.

**Ejemplo:** Todos los eventos de EventID 12 (Registry Object create/delete) que tienen los campos `[EventType, Image, ProcessGuid, ProcessId, RuleName, TargetObject, User, UtcTime]` con valores presentes generarán el mismo hash.

## Paso 2: Aplicar fingerprinting a la muestra

Aplicamos la función de fingerprinting a los 200,000 registros muestreados y agrupamos por fingerprint:

```python
structure_patterns = {}   # fingerprint → información del patrón
eventid_patterns = {}     # EventID → conjunto de fingerprints

for event in sample:
    event_id, computer, fields, fingerprint = parse_sysmon_event_detailed(xml_content)

    if fingerprint not in structure_patterns:
        structure_patterns[fingerprint] = {
            'count': 0, 'event_ids': set(),
            'computers': set(), 'field_count': len(fields)
        }

    structure_patterns[fingerprint]['count'] += 1
    structure_patterns[fingerprint]['event_ids'].add(event_id)
    eventid_patterns[event_id].add(fingerprint)
```

El resultado nos dice cuántos **patrones estructurales únicos** existen en todo el dataset.

## Paso 3: Resultados del análisis de consistencia

### 3a. Métricas generales

*(Los resultados se actualizarán con datos reales del notebook)*

### 3b. Consistencia por EventID

*(Se actualizará con la tabla de consistencia por EventID)*

### 3c. Análisis detallado de patrones

*(Se actualizará con los patrones más frecuentes)*

### 3d. Co-ocurrencia de campos

*(Se actualizará con el análisis de campos compartidos)*

### 3e. Reporte de consistencia

*(Se actualizará con las métricas de consistencia y recomendaciones)*

## Conclusiones e implicaciones

*(Se actualizará con las conclusiones del análisis)*
