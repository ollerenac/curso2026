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

### Integración con el parser XML

En la sección anterior construimos `sanitize_xml` y `parse_sysmon_event` para extraer datos del XML. Para este análisis, extendemos el parser con una función que además genera el fingerprint:

```python
def parse_sysmon_event_detailed(xml_str):
    """Parse XML con análisis estructural detallado."""
    try:
        clean_xml = sanitize_xml(xml_str)
        namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(clean_xml)

        system = root.find('ns:System', namespaces)
        if not system:
            return None, None, {}, None

        event_id = int(system.find('ns:EventID', namespaces).text)
        computer = system.find('ns:Computer', namespaces).text

        event_data = root.find('ns:EventData', namespaces)
        fields = {}
        if event_data:
            for data in event_data.findall('ns:Data', namespaces):
                name = data.get('Name')
                if name:
                    fields[name] = data.text if data.text else None

        fingerprint = generate_structure_fingerprint(event_id, fields)
        return event_id, computer, fields, fingerprint

    except Exception:
        return None, None, {}, None
```

La diferencia con `parse_sysmon_event` de la sección anterior es que esta versión devuelve **4 valores** en lugar de 3: añade el `fingerprint` que identifica la estructura del registro.

## Paso 2: Carga de datos y muestreo

Antes de aplicar el fingerprinting, necesitamos cargar una muestra representativa. A diferencia de la exploración anterior (que usó muestreo aleatorio), aquí usamos un **muestreo estratificado** — tomando registros a intervalos regulares para garantizar cobertura uniforme a lo largo del archivo:

```
Total de registros:     363,657
Muestras recolectadas:  200,000
Cobertura:              55.00%
Intervalo de muestreo:  cada 1 registro (los primeros 200,000)
```

Con 363,657 registros y un objetivo de 200,000 muestras, el intervalo resulta ser 1 — lo que significa que se toman los primeros 200,000 registros secuencialmente. Esto es suficiente para un análisis de consistencia estructural, ya que las variaciones de estructura (si existen) no dependen de la posición en el archivo.

## Paso 3: Aplicar fingerprinting a la muestra

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

## Paso 4: Resultados del análisis de consistencia

### 4a. Métricas generales

El fingerprinting de los 200,000 registros muestreados produce resultados reveladores:

```
Patrones estructurales únicos:   19
Registros analizados:            200,000
Parsing exitoso:                 200,000 (100.0%)
Errores de parsing:              0 (0.0%)
Patrón más frecuente:            62,489 registros
```

**Interpretación**: Exactamente 19 patrones estructurales para 19 EventIDs significa que **cada EventID tiene una estructura única y consistente** — una correspondencia perfecta 1:1. No hay variaciones internas dentro de ningún EventID.

La tasa de parsing del 100% confirma que el parser XML construido en la sección anterior funciona correctamente para todos los registros del dataset.

### 4b. Consistencia por EventID

El análisis por EventID revela que **los 19 EventIDs tienen estructura completamente consistente** — cada uno con un solo patrón estructural:

| EventID | Descripción | Registros | Campos | Hosts | Consistente |
|---------|------------|-----------|--------|-------|-------------|
| 1 | Process Creation | 649 | 23 | 4 | ✅ |
| 2 | File Creation Time Changed | 125 | 9 | 4 | ✅ |
| 3 | Network Connection | 8,001 | 18 | 4 | ✅ |
| 4 | Sysmon Service State Changed | 1 | 4 | 1 | ✅ |
| 5 | Process Terminated | 559 | 6 | 4 | ✅ |
| 6 | Driver Loaded | 51 | 7 | 3 | ✅ |
| 7 | Image/Library Loaded | 35,756 | 16 | 4 | ✅ |
| 8 | Create Remote Thread | 4 | 14 | 2 | ✅ |
| 9 | Raw Access Read | 863 | 7 | 4 | ✅ |
| 10 | Process Access | 57,364 | 13 | 3 | ✅ |
| 11 | File Create | 4,040 | 8 | 4 | ✅ |
| 12 | Registry Object create/delete | 62,489 | 8 | 4 | ✅ |
| 13 | Registry Value Set | 24,195 | 9 | 4 | ✅ |
| 15 | File Create Stream Hash | 6 | 10 | 2 | ✅ |
| 17 | Pipe Created | 309 | 8 | 4 | ✅ |
| 18 | Pipe Connected | 904 | 8 | 4 | ✅ |
| 23 | File Delete archived | 4,665 | 10 | 4 | ✅ |
| 24 | Clipboard Change | 10 | 10 | 3 | ✅ |
| 25 | Process Tampering | 5 | 7 | 4 | ✅ |

**Observaciones clave:**

- **Consistencia perfecta (19/19)**: Todos los EventIDs presentan un solo patrón estructural. Esto significa que podemos diseñar un esquema fijo por EventID sin preocuparnos por variaciones.
- **EventID 10** (Process Access) es el más frecuente con 57,364 registros, seguido de **EventID 12** (Registry Object create/delete) con 62,489.
- **EventID 8** (Create Remote Thread) aparece con solo 4 registros en 2 hosts — un evento raro pero de alto valor en detección de amenazas, ya que es una técnica común de inyección de código.
- La complejidad varía significativamente: desde 4 campos (EID 4, estado del servicio Sysmon) hasta 23 campos (EID 1, creación de procesos).
- Los eventos raros (EID 4, 8, 15, 24, 25) aparecen en menos hosts, lo cual es esperable dado su naturaleza específica.

### 4c. Análisis detallado de patrones

Los 5 patrones más frecuentes concentran el **93.91%** de todos los registros:

| # | EventID | Descripción | Registros | % | Campos |
|---|---------|------------|-----------|---|--------|
| 1 | 12 | Registry Object create/delete | 62,489 | 31.25% | 8 |
| 2 | 10 | Process Access | 57,364 | 28.68% | 13 |
| 3 | 7 | Image/Library Loaded | 35,756 | 17.88% | 16 |
| 4 | 13 | Registry Value Set | 24,195 | 12.10% | 9 |
| 5 | 3 | Network Connection | 8,001 | 4.00% | 18 |

Los 14 patrones restantes representan solo el 6.09% de los registros.

**Ejemplo de registro típico** (Patrón #1 — EventID 12, Registry Object create/delete):

```
EventID:      12
Computer:     WATERFALLS.boombox.local
@timestamp:   2025-03-19T06:09:10.088Z
Fields:
  • RuleName:      -
  • EventType:     CreateKey
  • UtcTime:       2025-03-19 06:09:10.088
  • ProcessGuid:   {3fc4fefd-de08-67da-0c00-000000004900}
  • ProcessId:     648
  • Image:         C:\Windows\system32\lsass.exe
  • TargetObject:  HKLM\System\CurrentControlSet\Services\Tcpip\Parameters
  • User:          NT AUTHORITY\SYSTEM
```

**Clasificación de patrones por frecuencia:**

```
Patrones COMUNES (≥5%):     4 patrones
Patrones INFRECUENTES (1-5%):  3 patrones
Patrones RAROS (<1%):      12 patrones
Total:                     19 patrones
```

Los 4 patrones comunes (EID 12, 10, 7, 13) representan la actividad de fondo típica de un servidor Windows: operaciones de registro, acceso entre procesos, carga de librerías y modificación de valores de registro. Los 12 patrones raros incluyen eventos de alto valor para detección como **EID 8** (Create Remote Thread, 4 registros) y **EID 4** (Sysmon Service State Changed, 1 registro).

### 4d. Co-ocurrencia de campos

El análisis de co-ocurrencia examina qué campos aparecen juntos y cuáles son compartidos entre EventIDs:

```
Campos únicos totales:            74
Combinaciones únicas de campos:   18
```

**¿Por qué 18 combinaciones para 19 EventIDs?** Porque **EventID 17** (Pipe Created) y **EventID 18** (Pipe Connected) comparten exactamente los mismos 8 campos. El fingerprint los distingue porque incluye el EventID en el hash, pero la estructura de campos es idéntica.

**Campos más frecuentes (top 10):**

| Campo | Registros | Presencia |
|-------|-----------|-----------|
| UtcTime | 199,996 | 100.0% |
| RuleName | 199,995 | 100.0% |
| Image | 142,576 | 71.3% |
| ProcessGuid | 142,576 | 71.3% |
| User | 142,576 | 71.3% |
| ProcessId | 142,576 | 71.3% |
| EventType | 87,897 | 43.9% |
| TargetObject | 86,684 | 43.3% |
| SourceUser | 57,368 | 28.7% |
| SourceImage | 57,368 | 28.7% |

**Hallazgos clave:**

- **`UtcTime`** y **`RuleName`** son prácticamente universales (presentes en el 100% de los registros). Son candidatos naturales para columnas comunes en el CSV final.
- **`Image`**, **`ProcessGuid`**, **`User`** y **`ProcessId`** aparecen en el 71.3% de los registros — presentes en todos los EventIDs excepto EID 4 (estado del servicio) y EID 10 (que usa `SourceImage`/`TargetImage` en lugar de `Image`).
- Dentro de cada EventID, **todos los campos tienen presencia del 100%** — no hay campos opcionales. Esto confirma que cada EventID tiene un esquema fijo y determinista.
- Los campos `Source*`/`Target*` (SourceImage, TargetImage, SourceUser, etc.) son exclusivos de EventIDs que modelan interacciones entre procesos (EID 8, 10).

### 4e. Reporte de consistencia

El análisis culmina con un reporte que consolida todas las métricas:

```
MÉTRICAS DE CONSISTENCIA:
   • Patrones estructurales únicos:       19
   • EventIDs analizados:                 19
   • EventIDs consistentes (1 patrón):    19
   • EventIDs inconsistentes:              0
   • Ratio de diversidad estructural:      0.010%

ANÁLISIS DE COBERTURA:
   • Top 3 patrones cubren:   77.8% de los datos
   • Top 5 patrones cubren:   93.9% de los datos
   • Top 10 patrones cubren:  99.5% de los datos

EVALUACIÓN GENERAL: ALTAMENTE CONSISTENTE
```

**Estrategia de manejo de campos:**

| Categoría | Cantidad | Estrategia |
|-----------|----------|------------|
| Campos siempre presentes | 2 (`UtcTime`, `RuleName`) | Extracción estándar |
| Campos condicionales | 4 (`Image`, `ProcessGuid`, `User`, `ProcessId`) | Manejo de nulos requerido |
| Campos raros | 68 | Exclusión o manejo especial |

Los 2 campos universales (`UtcTime`, `RuleName`) aparecen en todos los EventIDs. Los 4 campos condicionales están presentes en el 71.3% de los registros — ausentes solo en EventIDs que usan nomenclatura diferente (como `SourceImage`/`TargetImage` en EID 10). Los 68 campos raros son específicos de uno o pocos EventIDs.

**Recomendación**: Procesamiento **EventID-específico** — cada EventID tiene un esquema fijo y determinista que permite diseñar un conversor JSONL → CSV con mapeo directo de campos.

## Conclusiones e implicaciones

El análisis de consistencia estructural arroja un resultado óptimo para el diseño del conversor:

1. **Consistencia perfecta (19/19)**: Cada EventID presenta un solo patrón estructural sin variaciones. No hay campos opcionales ni esquemas alternativos dentro del mismo tipo de evento.

2. **Correspondencia 1:1 entre patrones y EventIDs**: Los 19 patrones únicos corresponden exactamente a los 19 EventIDs, con la particularidad de que EID 17 y EID 18 comparten la misma estructura de campos (diferenciados solo por el EventID en el fingerprint).

3. **Concentración de datos**: El 93.9% de los registros se concentra en solo 5 EventIDs (12, 10, 7, 13, 3), lo que permite priorizar la optimización del conversor para estos tipos.

4. **74 campos únicos con jerarquía clara**: 2 universales, 4 comunes, 68 específicos por EventID. Esta estructura facilita un diseño de CSV con columnas comunes + columnas específicas.

**Implicación para el preprocesamiento**: Podemos proceder con confianza a diseñar un conversor JSONL → CSV que genere un archivo CSV por EventID, donde cada archivo tiene un esquema de columnas fijo y predecible. Esta es la tarea de la siguiente sección.
