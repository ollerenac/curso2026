# Extracción de Raw Data

**Duración**: 45 minutos

## Contexto: ¿Dónde están los datos?

En la sección anterior vimos que nuestra infraestructura virtual genera dos tipos de telemetría:

| Dominio | Fuente | Tipo de datos | Descripción |
|---------|--------|---------------|-------------|
| **Host** | Sysmon (System Monitor) | Eventos de sistema | Creación de procesos, conexiones de red, modificaciones de registro, acceso a archivos |
| **Red** | NetFlow | Tráfico de red | Flujos de comunicación entre hosts: IPs, puertos, protocolos, volúmenes de datos |

Estos datos son recolectados de forma continua y centralizada en un clúster de **Elasticsearch**, un motor de búsqueda y analítica distribuido ampliamente utilizado en entornos de ciberseguridad para la gestión de logs y eventos.

### Flujo de datos

```
┌──────────────────────────────────────────────────────────────────┐
│                   Infraestructura Virtual                        │
│                                                                  │
│  ┌─────────┐    ┌─────────┐    ┌──────────────┐                │
│  │  ITM2   │    │  ITM4   │    │     ITMX     │                │
│  │ Servers │    │ Clients │    │ Elasticsearch │◄──────────┐   │
│  └────┬────┘    └────┬────┘    └──────┬───────┘           │   │
│       │              │                │                    │   │
│       │   Sysmon + NetFlow            │                    │   │
│       └──────────────┴────────────────┘                    │   │
│                      │                               Beats/    │
│                      │                              Agents     │
│                      └─────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                       │
                       │  Script de extracción
                       │  (Elasticsearch API)
                       ▼
              ┌─────────────────┐
              │ Archivos .jsonl │
              │                 │
              │  sysmon.jsonl   │
              │  netflow.jsonl  │
              └────────┬────────┘
                       │
                       ▼
              Preprocesamiento
              (Sesión 1.3)
```

### Estructuras de datos en JSON

Antes de hablar del formato de exportación, es importante entender las estructuras de datos que maneja **JSON** (JavaScript Object Notation), ya que los datos de Elasticsearch se almacenan internamente en este formato.

JSON soporta los siguientes tipos de datos:

| Tipo | Python equivalente | Ejemplo JSON |
|------|-------------------|--------------|
| Objeto | `dict` | `{"clave": "valor"}` |
| Array | `list` | `[1, 2, 3]` |
| String | `str` | `"texto"` |
| Número | `int` / `float` | `42`, `3.14` |
| Booleano | `bool` | `true`, `false` |
| Nulo | `None` | `null` |

La estructura más relevante para nuestros datos es el **objeto** (equivalente a un diccionario en Python), que almacena pares clave-valor:

```json
{
  "process": {
    "name": "cmd.exe",
    "pid": 1234
  }
}
```

Un aspecto clave de JSON es que permite **anidamiento**: un objeto puede contener otros objetos, arrays, o cualquier combinación de tipos. Esto es fundamental porque los eventos de seguridad tienen estructuras jerárquicas complejas. Por ejemplo, un evento de Sysmon puede contener:

```json
{
  "@timestamp": "2025-01-29T04:24:54.863Z",
  "event": {
    "category": "process",
    "action": "Process Create"
  },
  "process": {
    "name": "cmd.exe",
    "pid": 1234,
    "args": ["/c", "whoami"]
  },
  "host": {
    "name": "ITM2-DC",
    "ip": ["10.2.0.10"]
  }
}
```

Aquí vemos objetos dentro de objetos (`event`, `process`, `host`), arrays de strings (`args`, `ip`) y tipos primitivos mezclados. Esta riqueza estructural es precisamente lo que necesitamos preservar.

### Formatos de almacenamiento: ¿CSV, JSON o JSONL?

Cuando exportamos datos desde Elasticsearch, debemos elegir un formato de archivo. Comparemos las tres opciones principales usando el mismo evento simplificado:

**CSV** — Formato tabular, una fila por registro:

```csv
@timestamp,event.category,process.name,process.pid,process.args
2025-01-29T04:24:54.863Z,process,cmd.exe,1234,"/c whoami"
```

**JSON** — Un array que contiene todos los documentos:

```json
[
  {"@timestamp": "2025-01-29T04:24:54.863Z", "event": {"category": "process"}, "process": {"name": "cmd.exe"}},
  {"@timestamp": "2025-01-29T04:24:55.120Z", "event": {"category": "network"}, "source": {"ip": "10.2.0.10"}}
]
```

**JSONL** (JSON Lines) — Un documento JSON por línea, sin array contenedor:

```json
{"@timestamp": "2025-01-29T04:24:54.863Z", "event": {"category": "process"}, "process": {"name": "cmd.exe"}}
{"@timestamp": "2025-01-29T04:24:55.120Z", "event": {"category": "network"}, "source": {"ip": "10.2.0.10"}}
```

| Criterio | CSV | JSON | JSONL |
|----------|-----|------|-------|
| Preserva estructura anidada | No — requiere aplanar campos (`event.category`) | Si | Si |
| Carga en memoria | Línea por línea | **Todo el archivo** (el array completo) | Línea por línea |
| Campos variables entre registros | Problemático — requiere columnas para todos los campos posibles | Si | Si |
| Compatibilidad con pandas | `pd.read_csv()` | `pd.read_json()` | `pd.read_json(..., lines=True)` |

### ¿Por qué JSONL?

Nuestro script exporta en formato JSONL porque combina las ventajas de JSON (preservar la estructura jerárquica) con la eficiencia de procesamiento línea por línea:

- **Preserva la estructura original** de los documentos de Elasticsearch sin pérdida de campos ni aplanamiento.
- **Es compatible con procesamiento en streaming**, permitiendo leer archivos de gran tamaño línea por línea sin cargar todo en memoria — crítico cuando exportamos millones de eventos.
- **Tolera campos heterogéneos**: un evento de Sysmon y uno de NetFlow tienen campos completamente diferentes, y JSONL los maneja sin problema.
- **Facilita el preprocesamiento posterior** con herramientas como `pandas` (`pd.read_json(..., lines=True)`).

## Walkthrough del Script de Extracción

El script `1_elastic_index_downloader.py` implementa un pipeline de extracción en 5 pasos. A continuación, analizamos cada componente.

### Paso 1: Configuración y Conexión

Primero, se establece la conexión con el clúster de Elasticsearch. En un entorno de laboratorio, es común desactivar la verificación de certificados SSL ya que se utilizan certificados autofirmados.

```python
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

# Configuración global
es_host = "<ES_HOST>"           # Ejemplo: "https://10.2.0.20:9200"
username = "<ES_USER>"          # Usuario de Elasticsearch
password = "<ES_PASSWORD>"      # Contraseña de Elasticsearch
keywords = ['sysmon', 'network_traffic']
output_dir = "./"

def connect_elasticsearch():
    """
    Crea una conexión segura al clúster de Elasticsearch.
    """
    return Elasticsearch(
        hosts=[es_host],                         # Endpoint del clúster
        basic_auth=(username, password),         # Autenticación usuario/contraseña
        verify_certs=False,                      # Desactivar verificación SSL (entorno lab)
        ssl_show_warn=False                      # Suprimir advertencias SSL
    )


def test_connection(es):
    """
    Valida la conexión con un ping de prueba.
    """
    try:
        return es.ping()
    except Exception as e:
        print(f"Connection failed: {e}")
        return False
```

**Puntos clave:**
- La librería `elasticsearch-py` proporciona el cliente oficial de Python para comunicarse con Elasticsearch.
- El helper `scan` será utilizado más adelante para la extracción eficiente de grandes volúmenes de datos.
- `verify_certs=False` es aceptable **únicamente** en entornos de laboratorio controlados. En producción, siempre se deben validar los certificados.

### Paso 2: Descubrimiento de Índices

Elasticsearch organiza los datos en **índices**, que son análogos a tablas en una base de datos relacional. En nuestro entorno, cada fuente de telemetría genera sus propios índices, típicamente con nombres que contienen palabras clave como `sysmon` o `network_traffic`.

```python
def list_relevant_indices(es, keywords):
    """
    Descubre índices que contienen palabras clave de seguridad.

    Args:
        es: Cliente de Elasticsearch
        keywords: Lista de palabras clave para filtrar (ej: ['sysmon', 'network_traffic'])

    Returns:
        Lista de diccionarios con metadatos del índice (nombre, tamaño, fecha de creación)
    """
    try:
        # Consultar al clúster todos los índices con metadatos
        response = es.cat.indices(format="json", h="index,store.size,creation.date")

        # Filtrar índices que contengan las palabras clave de seguridad
        return [
            {
                "name": idx["index"],
                "size": idx.get("store.size", "0b"),
                "created": datetime.fromtimestamp(
                    int(idx["creation.date"]) / 1000, tz=timezone.utc
                )
            }
            for idx in response
            if any(kw in idx["index"] for kw in keywords)
        ]
    except Exception as e:
        print(f"Error listing indices: {e}")
        return []
```

**Puntos clave:**
- `es.cat.indices()` es una API administrativa de Elasticsearch que retorna información sobre todos los índices del clúster.
- El filtrado por `keywords` permite seleccionar solo los índices relevantes para nuestra investigación, descartando índices del sistema u otros datos no relacionados.
- Cada índice tiene metadatos útiles: nombre, tamaño en disco y fecha de creación.

### Paso 3: Selección Interactiva de Índices

Una vez descubiertos los índices relevantes, el script presenta una interfaz interactiva para que el usuario seleccione cuáles desea descargar.

```python
def display_indices_selector(indices):
    """
    Interfaz interactiva para seleccionar índices a procesar.

    Args:
        indices: Lista de diccionarios de índices

    Returns:
        Lista de nombres de índices seleccionados
    """
    print(f"\nFound {len(indices)} relevant indices:")
    for i, idx in enumerate(indices, 1):
        print(f"{i:>3}. {idx['name']} ({idx['size']}) [Created: {idx['created'].strftime('%Y-%m-%d')}]")

    while True:
        selection = input("\nSelect indices (comma-separated numbers, 'all', or 'exit'): ").strip().lower()

        if selection == "exit":
            return []

        if selection == "all":
            return [idx["name"] for idx in indices]

        try:
            selected_indices = [
                indices[int(num) - 1]["name"]
                for num in selection.split(",")
                if num.strip().isdigit()
            ]
            if selected_indices:
                return list(set(selected_indices))  # Eliminar duplicados
            print("No valid selection. Please try again.")
        except (IndexError, ValueError):
            print("Invalid input format. Use numbers separated by commas.")
```

**Puntos clave:**
- El patrón interactivo permite flexibilidad: descargar todos los índices o solo un subconjunto específico.
- `enumerate(indices, 1)` presenta los índices con numeración comenzando desde 1, facilitando la selección por parte del usuario.
- `list(set(...))` elimina selecciones duplicadas.

### Paso 4: Definición del Rango Temporal

Los ataques APT tienen una línea temporal definida. Esta función permite acotar la extracción a un rango de tiempo específico, lo cual es esencial para:
- Reducir el volumen de datos descargados.
- Focalizar la extracción en el periodo donde ocurrió el ataque.

```python
TIMESTAMP_FORMAT = "%b %d, %Y @ %H:%M:%S.%f"

def parse_utc_time(time_str):
    """
    Convierte una cadena de tiempo legible en un objeto datetime UTC.

    Args:
        time_str: Cadena en formato "Jan 29, 2025 @ 04:24:54.863"

    Returns:
        Objeto datetime en UTC, None si falla el parsing
    """
    try:
        time_str = time_str.split(" (UTC)")[0].strip()
        return datetime.strptime(time_str, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as e:
        print(f"Time parsing error: {e}")
        print(f"Expected format: {TIMESTAMP_FORMAT} (UTC)")
        return None
```

**Puntos clave:**
- El formato de timestamp coincide con el formato utilizado por la interfaz **Kibana** de Elasticsearch, lo que facilita copiar y pegar rangos de tiempo directamente desde la interfaz web.
- Todo se maneja en **UTC** para evitar inconsistencias entre zonas horarias en un entorno distribuido con múltiples hosts.

### Paso 5: Exportación de Datos

Esta es la función principal de extracción. Utiliza la **Scroll API** de Elasticsearch (a través del helper `scan`) para exportar eficientemente grandes volúmenes de datos.

```python
def export_index_data(es, index_name, start_time, end_time):
    """
    Exporta datos de un índice específico dentro de un rango temporal a un archivo JSONL.

    Args:
        es: Cliente de Elasticsearch
        index_name: Nombre del índice a exportar
        start_time: Inicio del rango temporal (UTC)
        end_time: Fin del rango temporal (UTC)

    Returns:
        True si la exportación fue exitosa, False en caso contrario
    """
    os.makedirs(output_dir, exist_ok=True)

    # Crear nombre de archivo seguro a partir del nombre del índice
    safe_name = index_name.replace(":", "_").replace(".", "-")
    filename = os.path.join(output_dir, f"{safe_name}.jsonl")

    # Construir query de Elasticsearch con filtro por rango temporal
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),            # Mayor o igual que inicio
                    "lte": end_time.isoformat(),              # Menor o igual que fin
                    "format": "strict_date_optional_time"     # Formato ISO 8601
                }
            }
        }
    }

    try:
        with open(filename, "w") as f:
            count = 0
            # scan() implementa la Scroll API para iterar eficientemente
            # sobre grandes conjuntos de resultados sin cargar todo en memoria
            for hit in scan(es, index=index_name, query=query):
                f.write(json.dumps(hit["_source"]) + "\n")
                count += 1

        print(f"Success: {count} documents from {index_name} -> {filename}")
        return True
    except Exception as e:
        print(f"Failed to export {index_name}: {e}")
        return False
```

**Puntos clave:**
- **`scan()` vs búsqueda normal**: Una búsqueda estándar en Elasticsearch retorna un máximo de 10,000 resultados. El helper `scan` implementa la Scroll API, que permite iterar sobre **todos** los documentos que coinciden con la consulta, sin importar el volumen.
- **Query `range` sobre `@timestamp`**: Este es el campo estándar de timestamp en Elasticsearch. El filtro acota los resultados al periodo exacto del ataque.
- **`hit["_source"]`**: En Elasticsearch, `_source` contiene el documento original tal como fue indexado, sin metadatos internos del motor.
- Los archivos se escriben de forma incremental (línea por línea), lo que permite manejar exportaciones de millones de documentos sin problemas de memoria.

### Orquestación: Función Principal

La función `main()` conecta todas las piezas anteriores en un flujo secuencial:

```python
def main():
    # Paso 1: Establecer conexión
    es = connect_elasticsearch()
    if not test_connection(es):
        return

    # Paso 2: Descubrir índices relevantes
    indices = list_relevant_indices(es, keywords)
    if not indices:
        return

    # Paso 3: Selección interactiva de índices
    selected_indices = display_indices_selector(indices)
    if not selected_indices:
        return

    # Paso 4: Obtener rango temporal del usuario
    start_time = parse_utc_time(input("Start time: "))
    end_time = parse_utc_time(input("End time: "))
    if not all([start_time, end_time]):
        return

    # Paso 5: Extraer datos de cada índice seleccionado
    for index in selected_indices:
        export_index_data(es, index, start_time, end_time)
```

## Actividad Práctica

### Ejercicio: Análisis del Pipeline

Dado el siguiente escenario:

> Se ejecutó un ataque APT simulado sobre la infraestructura virtual entre el **29 de enero de 2025 a las 04:00 UTC** y el **29 de enero de 2025 a las 08:00 UTC**. El clúster de Elasticsearch contiene 15 índices, de los cuales 4 contienen la palabra `sysmon` y 3 contienen `network_traffic`.

Responde las siguientes preguntas:

1. **¿Cuántos archivos JSONL generará el script** si el usuario selecciona "all" en el selector de índices?

2. **¿Por qué es importante definir un rango temporal acotado** en lugar de exportar todo el contenido de los índices?

3. **¿Qué sucedería si usáramos una búsqueda normal de Elasticsearch** (sin `scan`) para un índice con 500,000 documentos?

4. **Observa la configuración del script**. Si necesitaras agregar un tercer dominio de datos (por ejemplo, logs de autenticación almacenados en índices con la palabra `auth`), **¿qué línea del código modificarías?**

### Resultado Esperado

Al finalizar esta sección, deberías comprender:

- Cómo se conecta el script de extracción con la infraestructura presentada en la introducción.
- El rol de Elasticsearch como punto centralizado de recolección de telemetría.
- Cómo la Scroll API permite extraer grandes volúmenes de datos de forma eficiente.
- El formato JSONL como puente entre Elasticsearch y las etapas de preprocesamiento que veremos en la siguiente sección.
