# Exploración de Datos NetFlow

**Duración**: 50 minutos

## Contexto

En las secciones anteriores exploramos los datos Sysmon: descubrimos la estructura de doble capa (JSON + XML incrustado), prototipamos el parser XML, y verificamos la consistencia estructural de los 363,657 registros. Ahora aplicamos la **misma metodología de exploración** al segundo dominio de telemetría: el tráfico de red capturado como NetFlow.

El archivo NetFlow de `run-01` se encuentra en:

```
dataset/run-01-apt-1/
└── ds-logs-network_traffic-flow-default-run-01.jsonl   (1.1 GB, 569,443 registros)
```

La diferencia fundamental con Sysmon es que los datos NetFlow son **JSON anidado puro** — no hay XML incrustado en ningún campo. Esto significa que la complejidad no está en el parsing de un formato externo, sino en la **navegación de estructuras anidadas** dentro del propio JSON.

```{note}
El análisis completo con celdas interactivas y resultados detallados se encuentra en el notebook `4a-exploratory_network-traffic-flow-index.ipynb`. Los números y hallazgos de esta sección provienen directamente de ese notebook.
```

```{admonition} Antes de continuar — haz una predicción
:class: note

Ya conoces la estructura de Sysmon: JSON con XML incrustado, namespaces XML, y 19 tipos de EventID. Ahora explorarás NetFlow:

1. ¿Esperarías la misma complejidad de **doble capa** (JSON + otro formato incrustado), o una estructura más directa?
2. ¿Cuántas claves de primer nivel crees que tendrá un registro NetFlow — más o menos que las 16 de Sysmon?
3. ¿Todos los registros NetFlow tendrán **exactamente los mismos campos**, o habrá campos opcionales?

Anota tus predicciones y compáralas con los resultados.
```

## Paso 1: La unidad mínima — un registro NetFlow

Como siempre, comenzamos leyendo **una sola línea** del archivo JSONL:

```python
import json
import os

TARGET_PATH = "/ruta/al/dataset/run-01-apt-1/"
TARGET_FILE = "ds-logs-network_traffic-flow-default-run-01.jsonl"
TARGET_FILEPATH = os.path.join(TARGET_PATH, TARGET_FILE)

# Leer la primera línea del archivo
with open(TARGET_FILEPATH, 'r') as f:
    first_line = f.readline()

record = json.loads(first_line)
```

¿Qué tipo de dato obtenemos?

```python
>>> type(record)
<class 'dict'>

>>> len(record)
12
```

Es un diccionario con **12 claves de primer nivel**. Veamos cuáles son:

```python
>>> for key, value in record.items():
...     print(f"{key:20s} -> {type(value).__name__}")
```

```
process              -> dict
agent                -> dict
destination          -> dict
elastic_agent        -> dict
network_traffic      -> dict
source               -> dict
network              -> dict
@timestamp           -> str
ecs                  -> dict
data_stream          -> dict
host                 -> dict
event                -> dict
```

**Observaciones inmediatas:**

1. Hay **12 campos de primer nivel**. Casi todos son diccionarios (`dict`), con la excepción de `@timestamp` que es un string.
2. **No existe el campo `event.original`**. En Sysmon, este campo contenía el XML con los datos del evento. Aquí, los datos de red están directamente en los diccionarios `source`, `destination`, `network` y `network_traffic`.
3. Los campos relevantes para el tráfico de red (`source`, `destination`, `network`) están al mismo nivel que los metadatos de infraestructura (`agent`, `elastic_agent`, `ecs`).

Esta ausencia de XML es el contraste fundamental con Sysmon:

```
Sysmon:   JSON ─── event.original ─── XML (hay que parsear)
NetFlow:  JSON ─── datos anidados ─── diccionarios Python (acceso directo)
```

Veamos un fragmento representativo del registro (campos de red, sin los metadatos de infraestructura):

```json
{
    "source": {
        "port": 123,
        "bytes": 162,
        "ip": "10.1.0.6",
        "mac": "08-00-27-DD-98-2C",
        "packets": 1
    },
    "destination": {
        "port": 123,
        "bytes": 162,
        "ip": "10.1.0.4",
        "mac": "08-00-27-B1-0A-06",
        "packets": 1,
        "process": {
            "name": "svchost.exe",
            "pid": 380,
            "executable": "C:\\Windows\\System32\\svchost.exe",
            "ppid": 592,
            "args": ["C:\\Windows\\system32\\svchost.exe", "-k", "LocalService"],
            "start": "2025-03-19T14:04:16.907Z",
            "working_directory": ""
        }
    },
    "network": {
        "community_id": "1:oV4NZBbe8LDnUyQgq+a/zgO7oMc=",
        "bytes": 324,
        "transport": "udp",
        "type": "ipv4",
        "packets": 2
    },
    "@timestamp": "2025-03-19T06:12:20.121Z",
    "event": {
        "duration": 0,
        "action": "network_flow",
        "kind": "event",
        "start": "2025-03-19T06:11:20.929Z",
        "end": "2025-03-19T06:11:20.929Z",
        "category": ["network"],
        "type": ["connection", "end"]
    }
}
```

Los datos están **ya estructurados** como diccionarios Python. No hay necesidad de un parser XML ni de funciones de sanitización.

## Paso 2: Estructura de primer nivel

Para generalizar más allá de un solo registro, analizamos una muestra representativa. El notebook `4a` analizó 200,000 registros aleatorios y encontró la siguiente distribución de campos:

```python
from collections import Counter, defaultdict
import random

# Contar total de registros
total_records = 0
with open(TARGET_FILEPATH, 'r') as f:
    for line in f:
        total_records += 1
print(f"Total records: {total_records:,}")
# Total records: 569,443

# Muestrear 200,000 registros
SAMPLE_SIZE = 200_000
sample_indices = set(random.sample(range(total_records), SAMPLE_SIZE))

# Analizar campos de primer nivel
field_counter = Counter()
field_types = defaultdict(Counter)

with open(TARGET_FILEPATH, 'r') as f:
    for idx, line in enumerate(f):
        if idx in sample_indices:
            record = json.loads(line)
            for key, value in record.items():
                field_counter[key] += 1
                field_types[key][type(value).__name__] += 1
```

El resultado muestra 12 campos totales, pero con una diferencia importante: **11 están siempre presentes y 1 es opcional**.

| Campo | Conteo | Porcentaje | Tipo |
|-------|--------|------------|------|
| `agent` | 200,000 | 100.0% | dict |
| `destination` | 200,000 | 100.0% | dict |
| `elastic_agent` | 200,000 | 100.0% | dict |
| `network_traffic` | 200,000 | 100.0% | dict |
| `source` | 200,000 | 100.0% | dict |
| `network` | 200,000 | 100.0% | dict |
| `@timestamp` | 200,000 | 100.0% | str |
| `ecs` | 200,000 | 100.0% | dict |
| `data_stream` | 200,000 | 100.0% | dict |
| `host` | 200,000 | 100.0% | dict |
| `event` | 200,000 | 100.0% | dict |
| `process` | 97,947 | **49.0%** | dict |

**Hallazgo clave:** El campo `process` solo aparece en el **62.8%** de los registros. Esto se debe a que Packetbeat (el agente de captura de red) solo puede asociar un flujo de red con un proceso del sistema operativo cuando tiene suficiente información para hacer esa correlación. Los flujos donde no se identifica el proceso origen/destino simplemente omiten el campo.

```{important}
Este porcentaje (49.0%) corresponde **exclusivamente a la ejecución `run-01-apt-1`**. Nuestro dataset contiene 48 ejecuciones (*runs*) con diferentes campañas APT, y cada una puede presentar una proporción diferente de registros con información de proceso — dependiendo de la naturaleza del ataque, los servicios activos en la red, y las condiciones de captura. En sesiones posteriores analizaremos la consistencia estructural a lo largo de todos los runs para determinar si este patrón se mantiene o varía.
```

Veamos la diferencia entre un registro con y sin `process`:

```python
# Registro CON process: 12 claves de primer nivel
>>> record_con_process = json.loads(lineas[0])
>>> len(record_con_process)
12

# Registro SIN process: 11 claves de primer nivel
>>> record_sin_process = json.loads(lineas[1])
>>> len(record_sin_process)
11
>>> 'process' in record_sin_process
False
```

A diferencia de Sysmon, donde la variación proviene de 21 esquemas de EventID diferentes, en NetFlow la variación proviene de una **única distinción binaria**: presencia o ausencia de `process`.

## Paso 3: Estructura anidada — navegación con dot-notation

Los datos de red están distribuidos en diccionarios anidados. Para acceder a un campo específico, navegamos la jerarquía usando la notación de puntos (*dot-notation*):

```python
# Acceso directo a campos anidados
>>> record['source']['ip']
'10.1.0.6'

>>> record['destination']['port']
123

>>> record['network']['transport']
'udp'

>>> record['destination']['process']['name']
'svchost.exe'
```

Para explorar sistemáticamente **todos** los caminos posibles en la jerarquía, usamos una función recursiva que genera las rutas con dot-notation:

```python
def get_all_field_paths(obj, prefix="", max_depth=4, current_depth=0):
    """Recorre recursivamente un diccionario y genera todas las rutas de campo."""
    paths = {}
    if current_depth >= max_depth:
        return paths

    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{prefix}.{key}" if prefix else key
            paths[new_path] = type(value).__name__
            # Recursión para diccionarios anidados
            paths.update(get_all_field_paths(value, new_path, max_depth, current_depth + 1))
    elif isinstance(obj, list) and obj:
        # Para listas, explorar el primer elemento
        array_path = f"{prefix}[0]"
        paths[array_path] = type(obj[0]).__name__
        paths.update(get_all_field_paths(obj[0], array_path, max_depth, current_depth + 1))

    return paths
```

Aplicando esta función a múltiples registros de la muestra, el análisis identificó **96 rutas de campo únicas** distribuidas en 12 grupos de primer nivel:

```
@timestamp               1 ruta    ─── valor directo (str)
agent                    6 rutas   ─── agente Packetbeat
data_stream              4 rutas   ─── metadatos del índice
destination             15 rutas   ─── IP, puerto, bytes, MAC, paquetes + process
ecs                      2 rutas   ─── versión ECS
elastic_agent            4 rutas   ─── agente Elastic
event                   12 rutas   ─── tipo, categoría, duración, timestamps
host                    17 rutas   ─── hostname, OS, IPs, MACs, arquitectura
network                  6 rutas   ─── bytes totales, protocolo, community_id
network_traffic          4 rutas   ─── flow.id, flow.final
process                 10 rutas   ─── nombre, PID, ejecutable, args, parent
source                  15 rutas   ─── IP, puerto, bytes + process anidado
```

La jerarquía completa para los campos más relevantes se puede visualizar así:

```
registro NetFlow
├── source
│   ├── ip               "10.1.0.6"
│   ├── port             123
│   ├── bytes            162
│   ├── mac              "08-00-27-DD-98-2C"
│   ├── packets          1
│   └── process          (presente en algunos registros)
│       ├── name         "svchost.exe"
│       ├── pid          380
│       └── executable   "C:\\Windows\\System32\\svchost.exe"
│
├── destination
│   ├── ip               "10.1.0.4"
│   ├── port             123
│   ├── bytes            162
│   ├── mac              "08-00-27-B1-0A-06"
│   ├── packets          1
│   └── process          (presente en algunos registros)
│       ├── name         "svchost.exe"
│       ├── pid          380
│       ├── ppid         592
│       └── executable   "C:\\Windows\\System32\\svchost.exe"
│
├── network
│   ├── transport        "udp"
│   ├── type             "ipv4"
│   ├── bytes            324      (total = source.bytes + destination.bytes)
│   ├── packets          2
│   └── community_id     "1:oV4NZBbe8LDnUyQgq+a/zgO7oMc="
│
└── network_traffic
    └── flow
        ├── id           "EQIA////DP..."
        └── final        true
```

Para navegar esta jerarquía programáticamente, podemos usar una función auxiliar:

```python
def get_nested_value(record, dot_path, default=None):
    """Navega un diccionario anidado usando notación de puntos.

    Ejemplo: get_nested_value(record, 'destination.process.name')
    """
    keys = dot_path.split('.')
    current = record
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current

# Uso
>>> get_nested_value(record, 'source.ip')
'10.1.0.6'

>>> get_nested_value(record, 'destination.process.name')
'svchost.exe'

>>> get_nested_value(record, 'source.process.name', default='N/A')
'N/A'  # Este registro no tiene process en source
```

Esta función será esencial para el conversor CSV: permite extraer cualquier campo anidado de forma segura, devolviendo un valor por defecto cuando la ruta no existe.

## Paso 4: Análisis de calidad de datos

Con la estructura mapeada, evaluamos la **calidad** de los datos — ¿hay valores nulos, vacíos o inconsistentes?

El notebook `4a` analizó 200,000 registros muestreados aleatoriamente y los resultados son notablemente limpios:

| Campo | Valores vacíos | Completitud | Notas |
|-------|---------------|-------------|-------|
| `agent` | 0 | 100.0% | Siempre presente |
| `destination` | 0 | 100.0% | Siempre presente |
| `elastic_agent` | 0 | 100.0% | Siempre presente |
| `network_traffic` | 0 | 100.0% | Siempre presente |
| `source` | 0 | 100.0% | Siempre presente |
| `network` | 0 | 100.0% | Siempre presente |
| `@timestamp` | 0 | 100.0% | Longitud promedio: 24 caracteres |
| `ecs` | 0 | 100.0% | Siempre presente |
| `data_stream` | 0 | 100.0% | Siempre presente |
| `host` | 0 | 100.0% | Siempre presente |
| `event` | 0 | 100.0% | Siempre presente |
| `process` | 0 | 100.0% | **Cuando está presente** (49.0% de registros) |

**Hallazgo:** Los 11 campos obligatorios tienen **cero valores nulos o vacíos** en toda la muestra. Y el campo `process`, cuando está presente, también tiene completitud del 100% -- nunca aparece con un valor vacío o malformado.

Esto contrasta con lo que sucede en muchos datasets del mundo real, donde los valores nulos son frecuentes. La alta calidad se debe a que Packetbeat genera estos registros de forma automatizada y estandarizada -- no hay intervención humana que introduzca errores.

```python
# Verificar ausencia de nulos en campos obligatorios
for field_name in ['source', 'destination', 'network', '@timestamp', 'event', 'host']:
    null_count = sum(
        1 for sample in random_samples
        if sample.get(field_name) is None
        or sample.get(field_name) == ""
    )
    print(f"{field_name:20s}: {null_count} nulos de {len(random_samples):,}")
```

```
source              : 0 nulos de 200,000
destination         : 0 nulos de 200,000
network             : 0 nulos de 200,000
@timestamp          : 0 nulos de 200,000
event               : 0 nulos de 200,000
host                : 0 nulos de 200,000
```

Para el conversor CSV, esto simplifica considerablemente el diseño: no necesitamos lógica de imputación de valores faltantes para los campos obligatorios. Solo necesitamos manejar la **ausencia del campo `process`** en el 51.0% de los registros.

## Paso 5: Contraste con el dominio Sysmon

Habiendo explorado ambos dominios de telemetría, podemos establecer una comparación directa que será fundamental para el diseño de los conversores CSV:

| Aspecto | Sysmon | NetFlow |
|---------|--------|---------|
| Formato interno | XML en `event.original` | JSON anidado puro |
| Parsing necesario | XML namespace-aware + sanitización | Navegación de diccionarios |
| Registros (run-01) | 363,657 | 569,443 |
| Campos de primer nivel | 16 (todos constantes) | 12 (11 fijos + 1 opcional) |
| Fuente de variación | 21 esquemas de EventID | Presencia/ausencia de `process` |
| Campos nulos | 0% en `EventID`, `Computer` | 0% en 11 campos obligatorios |
| Rutas de campo únicas | 74 (a través de 21 EventIDs) | 96 (en la jerarquía JSON) |
| Complejidad del parser | Alta (XML + namespaces + limpieza) | Baja (acceso directo a dict) |

**Observación sobre el conteo de campos:** A primera vista puede parecer contraintuitivo que NetFlow tenga **más** rutas de campo (96) que Sysmon (74), dado que los datos de red son conceptualmente "más simples" que los eventos de sistema operativo. Esto se explica porque:

1. NetFlow tiene **información duplicada en diferentes niveles**: `source.process` y `destination.process` contienen campos similares, además del `process` de primer nivel.
2. El campo `host` incluye una sub-jerarquía detallada del sistema operativo (`host.os.name`, `host.os.kernel`, `host.os.build`, etc.) con 7 rutas adicionales.
3. Sysmon tiene muchos campos, pero están todos en un solo nivel plano dentro del XML `<EventData>` -- no se anidan.

La implicación práctica es que cada dominio requiere un **conversor CSV independiente** con una estrategia de aplanamiento (*flattening*) diferente:

```
Sysmon:   parse_xml() → extraer campos planos → CSV
NetFlow:  navegar_dict() → aplanar jerarquía → CSV
```

**Puntos clave:**

- NetFlow almacena los datos como **JSON anidado puro**, eliminando la necesidad del parsing XML y la sanitización que requiere Sysmon.
- De los 12 campos de primer nivel, **11 están siempre presentes** y el campo `process` aparece en el **49.0%** de los registros en `run-01-apt-1` (este porcentaje puede variar en otros runs).
- La jerarquía JSON contiene **96 rutas de campo únicas**, organizadas en una estructura de árbol con hasta 4 niveles de profundidad.
- La calidad de los datos es excepcional: **cero valores nulos o vacíos** en los campos obligatorios, y completitud del 100% para el campo `process` cuando está presente.

## Actividad Práctica

Responde a las siguientes preguntas basándote en lo que has aprendido en esta sección:

1. **¿Por qué NetFlow no necesita sanitización XML como Sysmon?** Explica qué diferencia estructural elimina la necesidad de funciones como `sanitize_xml` y el manejo de namespaces XML.

2. **¿Qué implicaciones tiene el campo `process` opcional (62.8%) para el conversor CSV?** Considera: ¿qué valor debería aparecer en las columnas de proceso cuando un registro no tiene el campo `process`? ¿Debería el CSV tener columnas separadas para `source.process.name` y `destination.process.name`?

3. **Compara el conteo de campos: Sysmon tiene 74 campos únicos a través de 21 EventIDs, mientras que NetFlow tiene 96 rutas en su jerarquía.** ¿Por qué NetFlow tiene más rutas a pesar de ser conceptualmente más simple? ¿Qué papel juega la duplicación de información (`source.process` vs `destination.process`) en este conteo?

4. **Diseña la función `get_nested_value` para un caso adicional:** Modifica la función para que acepte rutas con índices de lista, como `event.type[0]`. ¿Cómo manejarías el caso donde la lista está vacía?

## Resultado Esperado

Al finalizar esta sección, deberías comprender:

- La diferencia fundamental entre los formatos de datos de Sysmon (XML incrustado en JSON) y NetFlow (JSON anidado puro), y cómo esto afecta la estrategia de extracción.
- Cómo explorar sistemáticamente una estructura JSON anidada usando funciones recursivas y dot-notation.
- El significado del campo `process` opcional y su impacto en el diseño del conversor CSV.
- La calidad excepcional de los datos NetFlow (cero nulos) y por qué esto simplifica el procesamiento.
- La necesidad de diseñar **dos conversores CSV independientes** con estrategias de aplanamiento diferentes para cada dominio.

---

En la siguiente sección aplicaremos el análisis de **consistencia estructural** al dominio NetFlow, verificando si la estructura que hemos descubierto aquí se mantiene uniforme a lo largo de los 569,443 registros -- o si existen variaciones que debamos considerar.
