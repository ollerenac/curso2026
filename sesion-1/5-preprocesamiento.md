# Preprocesamiento: De JSONL a CSV Estructurado

**Duración**: 90 minutos

## Contexto: ¿Por qué necesitamos CSV?

En las secciones anteriores exploramos los datos crudos en formato JSONL y validamos su consistencia estructural. Ahora debemos transformarlos en un formato tabular (CSV) adecuado para análisis y machine learning.

Recordemos el estado actual de nuestros datos:

```
dataset/run-XX-apt-Y/
├── ds-logs-windows-sysmon-*.jsonl    ← Eventos Sysmon (XML embebido en JSON)
└── ds-logs-network_traffic-*.jsonl   ← Flujos NetFlow (JSON anidado)
```

El objetivo de esta sección es producir:

```
dataset/run-XX-apt-Y/
├── sysmon-run-XX.csv                 ← CSV tabular con todos los eventos Sysmon
├── netflow-run-XX.csv                ← CSV tabular con todos los flujos de red
├── log-sysmon-JSONL-to-csv-run-XX.json   ← Log de procesamiento Sysmon
└── log-netflow-JSONL-to-csv-run-XX.json  ← Log de procesamiento NetFlow
```

### ¿Por qué no usar pandas directamente?

Una primera aproximación sería simplemente cargar el JSONL con pandas:

```python
import pandas as pd
df = pd.read_json("sysmon.jsonl", lines=True)
```

Sin embargo, esto presenta varios problemas:

| Problema | Descripción |
|----------|-------------|
| **XML embebido** | Los eventos Sysmon contienen XML dentro del campo `event.original` — pandas no puede aplanarlo automáticamente |
| **Esquema variable** | Cada EventID de Sysmon tiene campos diferentes (ej: EventID 1 tiene `CommandLine`, EventID 3 tiene `DestinationIp`) |
| **Tipos de datos** | Los puertos llegan como `float` desde Elasticsearch (`443.0`), los GUIDs tienen llaves innecesarias |
| **Campos anidados** | NetFlow tiene hasta 3 niveles de anidamiento (`destination.process.name`) |
| **Volumen** | Archivos de cientos de miles de eventos requieren procesamiento paralelo |

Por estas razones, necesitamos scripts especializados que manejen cada dominio de datos según sus particularidades.

### Pipeline de preprocesamiento

El preprocesamiento se realiza en tres pasos, cada uno implementado por un script independiente:

```
┌───────────────────────────────────────────────────────────┐
│                    Preprocesamiento                        │
│                                                            │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │  Script 2    │   │  Script 3    │   │  Script 4    │  │
│  │  Sysmon      │   │  NetFlow     │   │  Limpieza    │  │
│  │  JSONL→CSV   │   │  JSONL→CSV   │   │  de Calidad  │  │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘  │
│         │                  │                   │           │
│         ▼                  ▼                   ▼           │
│   sysmon-run-XX.csv  netflow-run-XX.csv  sysmon-run-XX.csv│
│   (generación)       (generación)        (corrección)     │
│                                                            │
│  ◄── Independientes ──►              ◄── Secuencial ──►   │
└───────────────────────────────────────────────────────────┘
```

Los Scripts 2 y 3 son **independientes** y pueden ejecutarse en paralelo. El Script 4 es **secuencial** y debe ejecutarse después del Script 2, ya que corrige problemas de calidad en el CSV de Sysmon.

---

## Parte A: Conversión de Sysmon JSONL a CSV (Script 2)

### El desafío: XML dentro de JSON

A diferencia de NetFlow, donde los campos están directamente en el JSON, los eventos de Sysmon almacenan sus datos dentro de un bloque XML embebido en el campo `event.original`. Cada línea del JSONL tiene esta estructura:

```json
{
  "@timestamp": "2025-01-29T04:24:54.863Z",
  "event": {
    "original": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <EventID>1</EventID>
        <Computer>ITM2-DC.intmaniac.local</Computer>
      </System>
      <EventData>
        <Data Name='UtcTime'>2025-01-29 04:24:54.863</Data>
        <Data Name='ProcessGuid'>{12345-abcde-...}</Data>
        <Data Name='ProcessId'>1234</Data>
        <Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>
        <Data Name='CommandLine'>cmd.exe /c whoami</Data>
      </EventData>
    </Event>"
  }
}
```

El script debe:
1. Extraer el XML del campo JSON
2. Parsear el XML para obtener `EventID`, `Computer` y los campos de `EventData`
3. Mapear los campos según el esquema específico de cada EventID
4. Construir un registro tabular plano

### Arquitectura del script

El `SysmonCSVCreator` utiliza una arquitectura **multi-hilo** para paralelizar el procesamiento de archivos grandes:

```
┌─────────────────────────────────────────────────────────┐
│                  SysmonCSVCreator                         │
│                                                          │
│  Archivo JSONL                                           │
│       │                                                  │
│       ▼                                                  │
│  read_jsonl_in_chunks()                                  │
│       │                                                  │
│       ├──► Chunk 1 ──► ThreadPoolExecutor ──┐            │
│       ├──► Chunk 2 ──► (process_chunk)  ──┤            │
│       ├──► Chunk 3 ──►                    ──┤            │
│       └──► Chunk N ──►                    ──┘            │
│                                              │           │
│                                    merge_chunk_stats()   │
│                                              │           │
│                                              ▼           │
│                                     pd.DataFrame         │
│                                              │           │
│                                    clean_dataframe()     │
│                                              │           │
│                                              ▼           │
│                                        CSV final         │
└─────────────────────────────────────────────────────────┘
```

### Lectura y partición en chunks

El primer paso es leer el archivo JSONL y dividirlo en bloques de tamaño configurable para su procesamiento paralelo:

```python
def read_jsonl_in_chunks(self, jsonl_path: str) -> List[List[str]]:
    """
    Lee un archivo JSONL y lo divide en chunks para procesamiento paralelo.

    Args:
        jsonl_path: Ruta al archivo JSONL de entrada

    Returns:
        Lista de chunks, donde cada chunk es una lista de líneas JSON
    """
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    chunks = []
    for i in range(0, len(lines), self.chunk_size):
        chunks.append(lines[i:i + self.chunk_size])

    return chunks
```

**Puntos clave:**
- El `chunk_size` por defecto es **10,000 líneas** por bloque, configurable vía YAML.
- Al dividir en chunks, cada hilo de ejecución procesa un bloque independiente sin compartir estado.
- El número de workers se auto-detecta con `multiprocessing.cpu_count()` o se configura manualmente.

### Parsing de eventos Sysmon: de XML a diccionario

Cada línea JSONL contiene un evento con XML embebido. El parsing requiere dos etapas: primero sanitizar el XML (que puede contener caracteres inválidos), y luego extraer los campos:

```python
def sanitize_xml(self, xml_str: str) -> str:
    """
    Limpia caracteres inválidos y repara estructura XML corrupta.
    Utiliza BeautifulSoup como parser tolerante.
    """
    # Eliminar caracteres de control no válidos en XML
    xml_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_str)
    # Reparar con BeautifulSoup si es necesario
    soup = BeautifulSoup(xml_str, 'xml')
    return str(soup)


def parse_sysmon_event(self, xml_str: str) -> Tuple[Optional[int], Optional[str], Dict]:
    """
    Parsea un evento Sysmon desde XML a componentes estructurados.

    Args:
        xml_str: Cadena XML del campo event.original

    Returns:
        Tupla de (EventID, Computer hostname, diccionario de campos EventData)
    """
    try:
        xml_str = self.sanitize_xml(xml_str)
        root = ET.fromstring(xml_str)

        # Namespace de Windows Event Log
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # Extraer EventID del bloque <System>
        event_id = int(root.find('.//ns:EventID', ns).text)
        computer = root.find('.//ns:Computer', ns).text

        # Extraer todos los campos de <EventData>
        fields = {}
        for data in root.findall('.//ns:EventData/ns:Data', ns):
            name = data.get('Name')
            value = data.text
            if name and value:
                fields[name] = value.strip()

        return event_id, computer, fields

    except Exception:
        return None, None, {}
```

**Puntos clave:**
- **Sanitización XML**: Los eventos de Sysmon pueden contener caracteres de control (bytes `0x00`-`0x1f`) que son inválidos en XML. BeautifulSoup actúa como un parser tolerante que repara estas anomalías.
- **Namespace-aware parsing**: El XML de Windows Event Log usa el namespace `http://schemas.microsoft.com/win/2004/08/events/event`, que debe especificarse para que las búsquedas XPath funcionen correctamente.
- **Campos de EventData**: Cada `<Data Name="X">valor</Data>` se extrae como un par clave-valor en el diccionario `fields`.

### Esquema por EventID

Sysmon genera más de 20 tipos de eventos diferentes, cada uno con campos específicos. El script define un mapa de esquema que determina qué campos extraer para cada EventID:

```python
self.fields_per_eventid = {
    1:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'CommandLine',
         'CurrentDirectory', 'User', 'ParentProcessGuid', 'ParentProcessId',
         'ParentImage', 'ParentCommandLine', 'OriginalFileName',
         'IntegrityLevel', 'Hashes', 'LogonGuid', 'LogonId', 'TerminalSessionId'],
    3:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User',
         'Protocol', 'SourceIp', 'SourceHostname', 'SourcePort',
         'DestinationIp', 'DestinationHostname', 'DestinationPort'],
    5:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User'],
    7:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ImageLoaded',
         'Hashes', 'Signed', 'Signature'],
    10: ['UtcTime', 'SourceProcessGUID', 'SourceProcessId', 'SourceImage',
         'TargetProcessGUID', 'TargetProcessId', 'TargetImage',
         'GrantedAccess', 'CallTrace'],
    11: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename',
         'CreationUtcTime'],
    22: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'QueryName',
         'QueryResults', 'QueryStatus'],
    23: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename',
         'Hashes', 'IsExecutable'],
    # ... EventIDs 2, 6, 8, 9, 12, 13, 14, 15, 16, 17, 18, 24, 25
}
```

Los EventIDs más relevantes para la detección de APTs son:

| EventID | Nombre | Relevancia para APT |
|---------|--------|---------------------|
| 1 | Process Creation | Ejecución de herramientas maliciosas, shells, scripts |
| 3 | Network Connection | Comunicación C2, exfiltración, movimiento lateral |
| 7 | Image Loaded | DLL injection, side-loading |
| 10 | Process Access | Credential dumping (LSASS), injection |
| 11 | File Create | Descarga de payloads, creación de archivos maliciosos |
| 22 | DNS Query | Resolución de dominios C2 |
| 23 | File Delete | Anti-forensics, limpieza de huellas |

### Construcción de registros tabulares

Cada evento se convierte en un registro plano usando el esquema correspondiente a su EventID:

```python
def _build_event_record(self, event_id: int, computer: str,
                        fields: Dict, chunk_stats: Dict) -> Optional[Dict]:
    """
    Construye un registro tabular a partir de los campos parseados.

    Args:
        event_id: ID del tipo de evento Sysmon
        computer: Hostname del equipo origen
        fields: Diccionario de campos extraídos del XML
        chunk_stats: Diccionario de estadísticas del chunk (thread-safe)

    Returns:
        Diccionario plano listo para insertar en DataFrame, o None
    """
    schema = self.fields_per_eventid.get(event_id)
    if schema is None:
        chunk_stats['unknown_event_ids'].add(event_id)
        return None

    # Crear registro base con EventID y Computer
    record = {'EventID': event_id, 'Computer': computer}

    # Poblar campos según el esquema del EventID
    for field_name in schema:
        value = fields.get(field_name)
        # Conversiones especiales por tipo de campo
        if field_name in self.integer_columns:
            value = self.safe_int_conversion(value)
        elif field_name in self.guid_columns:
            value = self.clean_guid(value)
        record[field_name] = value

    return record
```

**Puntos clave:**
- **Esquema unión**: El CSV final contiene la **unión** de todos los campos de todos los EventIDs. Esto significa que un evento de tipo 1 (Process Creation) tendrá valores `NaN` en los campos específicos de tipo 3 (Network Connection) y viceversa.
- **Conversión de tipos**: Los campos enteros (`ProcessId`, puertos) se convierten con una función segura que maneja `NaN` y whitespace. Los GUIDs se limpian de llaves (`{...}`).

### Procesamiento multi-hilo

La función que orquesta el procesamiento paralelo utiliza `ThreadPoolExecutor`:

```python
def process_events(self, jsonl_path: str) -> pd.DataFrame:
    """
    Orquesta el procesamiento paralelo del archivo JSONL completo.

    Args:
        jsonl_path: Ruta al archivo JSONL de Sysmon

    Returns:
        DataFrame con todos los eventos procesados
    """
    chunks = self.read_jsonl_in_chunks(jsonl_path)
    all_records = []
    all_chunk_stats = []

    with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
        # Enviar cada chunk como una tarea independiente
        futures = {
            executor.submit(self.process_chunk, chunk, i): i
            for i, chunk in enumerate(chunks)
        }

        # Recoger resultados a medida que se completan
        for future in as_completed(futures):
            chunk_id = futures[future]
            records, chunk_stats = future.result()
            all_records.extend(records)
            all_chunk_stats.append(chunk_stats)

    self.merge_chunk_stats(all_chunk_stats)
    return pd.DataFrame(all_records)
```

**Puntos clave:**
- Se utiliza `ThreadPoolExecutor` en lugar de `ProcessPoolExecutor` porque la tarea principal es I/O-bound (lectura de archivo) con algo de CPU (parsing XML). Los hilos son suficientes para este caso de uso.
- `as_completed()` procesa los resultados en orden de finalización, no de envío, lo que permite una barra de progreso más fluida.
- Las estadísticas de cada chunk se agregan de forma thread-safe usando `threading.Lock`.

### Limpieza y optimización del DataFrame

Una vez construido el DataFrame con todos los registros, se aplican transformaciones para optimizar el almacenamiento y la usabilidad:

```python
def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Limpia y optimiza el DataFrame para ML.

    Transformaciones aplicadas:
    1. Trim de whitespace en columnas string
    2. Conversión de UtcTime a epoch milliseconds (columna 'timestamp')
    3. Optimización de tipos de datos
    4. Ordenamiento cronológico
    """
    # Convertir UtcTime (string) → timestamp (epoch milliseconds int64)
    df['timestamp'] = pd.to_datetime(df['UtcTime']).astype('int64') // 10**6
    df = df.drop(columns=['UtcTime'])

    # Optimización de tipos para reducir uso de memoria
    for col in self.integer_columns:
        if col in df.columns:
            df[col] = df[col].astype('Int64')       # Nullable integer

    for col in self.guid_columns:
        if col in df.columns:
            df[col] = df[col].astype('string')       # String dedicado

    # Columnas de baja cardinalidad como categorías
    if 'Computer' in df.columns:
        df['Computer'] = df['Computer'].astype('category')

    # Ordenar cronológicamente
    df = df.sort_values('timestamp').reset_index(drop=True)

    return df
```

**Puntos clave:**
- **Epoch milliseconds**: Se reemplaza el campo `UtcTime` (string datetime) por `timestamp` (entero de milisegundos desde epoch). Este formato es más eficiente para operaciones de correlación temporal entre Sysmon y NetFlow en etapas posteriores del pipeline.
- **Tipos nullable (`Int64`)**: Pandas usa `Int64` (con mayúscula) en lugar de `int64` para soportar valores `NaN` en columnas enteras — necesario porque no todos los eventos tienen todos los campos.
- **Categorías**: Columnas como `Computer` que tienen pocos valores únicos se almacenan como `category`, reduciendo significativamente el uso de memoria.

### Uso del script

```bash
# Modo auto-detección: detecta archivos automáticamente a partir del directorio del run
python 2_sysmon_csv_creator.py --apt-dir apt-1/apt-1-05-04-run-05

# Modo explícito: especificar archivos de entrada y salida manualmente
python 2_sysmon_csv_creator.py \
    --input dataset/run-05-apt-1/ds-logs-windows-sysmon-run05.jsonl \
    --output dataset/run-05-apt-1/sysmon-run-05.csv

# Opciones adicionales
python 2_sysmon_csv_creator.py --apt-dir apt-1/apt-1-05-04-run-05 \
    --config mi-config.yaml \    # Configuración personalizada
    --no-validate                # Omitir validación contra archivo existente
```

**Salida del script:**
```
╔══════════════════════════════════════════════════════════════╗
║              Sysmon JSONL → CSV Creator v2.0                ║
╚══════════════════════════════════════════════════════════════╝
Processing: ds-logs-windows-sysmon-run05.jsonl
Chunks: 42 (chunk_size=10000, workers=8)

[████████████████████████████████████████] 100% - 42/42 chunks

Results:
  Total events processed: 418,234
  Events by EventID: {1: 45231, 3: 89012, 5: 12340, 7: 98765, ...}
  XML parse errors: 3 (0.0007%)
  Output: dataset/run-05-apt-1/sysmon-run-05.csv (187.4 MB)
  Processing time: 34.2s
```

---

## Parte B: Conversión de NetFlow JSONL a CSV (Script 3)

### Diferencia estructural con Sysmon

Mientras que Sysmon embebe XML dentro de JSON, los datos de NetFlow ya están completamente en JSON con campos anidados. Cada línea JSONL es un documento con estructura jerárquica:

```json
{
  "@timestamp": "2025-01-29T04:25:12.000Z",
  "destination": {
    "ip": "10.2.0.10",
    "port": 443.0,
    "bytes": 15234,
    "packets": 12,
    "process": {
      "name": "svchost.exe",
      "pid": 2048
    }
  },
  "source": {
    "ip": "10.4.0.15",
    "port": 54321.0,
    "bytes": 8432
  },
  "network": {
    "transport": "tcp",
    "type": "ipv4",
    "community_id": "1:abc123..."
  },
  "network_traffic": {
    "flow_id": "CwqX9a3...",
    "community_id": "1:abc123..."
  },
  "host": {
    "name": "ITM4-PC1",
    "ip": ["10.4.0.15", "fe80::1"]
  }
}
```

El reto aquí no es parsear XML, sino **aplanar** esta estructura jerárquica de hasta 3 niveles de profundidad en un CSV tabular de 39 columnas.

### Mapeo de campos: JSON anidado a columnas planas

El `NetworkTrafficCSVCreator` define un mapeo explícito de 39 campos desde rutas JSON a nombres de columnas CSV:

```python
self.fields = {
    # Campos temporales (3)
    '@timestamp':                   'timestamp',
    'event.start':                  'event_start',
    'event.end':                    'event_end',

    # Destino (8)
    'destination.ip':               'destination_ip',
    'destination.port':             'destination_port',
    'destination.bytes':            'destination_bytes',
    'destination.packets':          'destination_packets',
    'destination.process.name':     'destination_process_name',
    'destination.process.pid':      'destination_process_pid',
    'destination.process.args':     'destination_process_args',
    'destination.mac':              'destination_mac',

    # Fuente (5 + 5 de proceso)
    'source.ip':                    'source_ip',
    'source.port':                  'source_port',
    'source.bytes':                 'source_bytes',
    'source.packets':               'source_packets',
    'source.mac':                   'source_mac',
    'source.process.name':          'source_process_name',
    'source.process.pid':           'source_process_pid',
    'source.process.args':          'source_process_args',
    'source.process.executable':    'source_process_executable',
    'source.process.entity_id':     'source_process_entity_id',

    # Red (5)
    'network.transport':            'network_transport',
    'network.type':                 'network_type',
    'network.community_id':         'network_community_id',
    'network.bytes':                'network_bytes',
    'network.packets':              'network_packets',

    # Tráfico de red (2)
    'network_traffic.community_id': 'network_traffic_community_id',
    'network_traffic.flow_id':      'network_traffic_flow_id',

    # Host (4)
    'host.name':                    'host_name',
    'host.ip':                      'host_ip',
    'host.mac':                     'host_mac',
    'host.hostname':                'host_hostname',

    # Evento (3)
    'event.action':                 'event_action',
    'event.type[0]':                'event_type',
    'event.category[0]':            'event_category',

    # Proceso local (2)
    'process.name':                 'process_name',
    'process.pid':                  'process_pid',
}
```

### Extracción de valores anidados

La función clave para navegar la estructura JSON anidada utiliza notación de puntos con soporte para índices de array:

```python
def get_nested_value(self, doc: dict, path: str) -> Any:
    """
    Extrae un valor de un diccionario anidado usando notación de puntos.

    Soporta:
    - Rutas simples: 'destination.ip' → doc['destination']['ip']
    - Índices de array: 'event.type[0]' → doc['event']['type'][0]
    - Arrays completos: 'host.ip' → doc['host']['ip'] (retorna lista)

    Args:
        doc: Documento JSON como diccionario Python
        path: Ruta en notación de puntos (ej: 'source.process.name')

    Returns:
        Valor extraído, o None si la ruta no existe
    """
    keys = path.split('.')
    current = doc

    for key in keys:
        if current is None:
            return None

        # Manejar índice de array: 'event.type[0]'
        match = re.match(r'(\w+)\[(\d+)\]', key)
        if match:
            field, index = match.group(1), int(match.group(2))
            current = current.get(field)
            if isinstance(current, list) and len(current) > index:
                current = current[index]
            else:
                return None
        else:
            current = current.get(key) if isinstance(current, dict) else None

    return current
```

**Puntos clave:**
- La función maneja de forma segura rutas que no existen (retorna `None` en lugar de lanzar `KeyError`).
- El soporte para índices de array (`event.type[0]`) es necesario porque Elasticsearch almacena algunos campos como arrays aunque típicamente contengan un solo elemento.
- Campos como `host.ip` que son arrays completos se mantienen como listas en el CSV.

### Corrección de tipos: puertos como float

Un artefacto conocido de Elasticsearch es que almacena los puertos de red como números de punto flotante (`443.0` en lugar de `443`). El script corrige esto:

```python
self.port_fields = ['destination.port', 'source.port']

# Durante el procesamiento de cada línea:
for json_path, csv_column in self.fields.items():
    value = self.get_nested_value(doc, json_path)

    # Corregir puertos float → int
    if json_path in self.port_fields and value is not None:
        try:
            value = int(float(value))
        except (ValueError, TypeError):
            pass

    record[csv_column] = value
```

### Estandarización temporal

NetFlow tiene **tres campos temporales** que representan diferentes momentos de cada flujo de red:

| Campo | Significado | Ejemplo |
|-------|-------------|---------|
| `@timestamp` | Momento de indexación en Elasticsearch | `2025-01-29T04:25:12.000Z` |
| `event.start` | Inicio del flujo de red | `2025-01-29T04:25:10.500Z` |
| `event.end` | Fin del flujo de red | `2025-01-29T04:25:14.200Z` |

Los tres se convierten a epoch milliseconds para consistencia con el formato de Sysmon:

```python
def _apply_temporal_sorting_and_standardization(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Estandariza los tres campos temporales de NetFlow a epoch milliseconds (int64).
    """
    temporal_columns = ['timestamp', 'event_start', 'event_end']

    for col in temporal_columns:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col]).astype('int64') // 10**6

    df = df.sort_values('timestamp').reset_index(drop=True)
    return df
```

**Puntos clave:**
- La estandarización a epoch milliseconds permite la **correlación temporal** entre Sysmon y NetFlow en el Script 5 (Sesión 2). Ambos dominios comparten la misma escala temporal.
- El ordenamiento cronológico facilita el análisis temporal posterior.

### Análisis exploratorio integrado

A diferencia del script de Sysmon, el script de NetFlow incluye un análisis exploratorio automático que genera estadísticas sobre el tráfico:

```python
def perform_exploratory_analysis(self, df: pd.DataFrame):
    """
    Análisis exploratorio del dataset NetFlow generado:
    - Distribución de protocolos (TCP, UDP, ICMP)
    - Puertos más frecuentes (destino)
    - Volumen de tráfico agrupado por flow_id (evita doble conteo)
    - Análisis de hosts (IPs más activas)
    - Porcentaje de datos faltantes por columna
    """
```

Un aspecto crucial es el **agrupamiento por `flow_id`** para calcular volúmenes de tráfico. Sin esta agrupación, los bytes se contarían múltiples veces porque un mismo flujo genera varios eventos (inicio, fin, conexión):

```python
# Agrupamiento por flow_id para evitar doble conteo
flow_grouped = df.groupby('network_traffic_flow_id').first()
total_bytes = flow_grouped['network_bytes'].sum()
```

### Uso del script

```bash
# Modo auto-detección
python 3_netflow_csv_creator.py --apt-dir apt-1/apt-1-05-04-run-05

# Modo explícito
python 3_netflow_csv_creator.py \
    --input dataset/run-05-apt-1/ds-logs-network_traffic-run05.jsonl \
    --output dataset/run-05-apt-1/netflow-run-05.csv
```

### Comparación: Script 2 vs Script 3

| Aspecto | Script 2 (Sysmon) | Script 3 (NetFlow) |
|---------|-------------------|-------------------|
| **Formato origen** | XML embebido en JSON | JSON anidado puro |
| **Parsing** | XML con namespace → campos | Notación de puntos → campos |
| **Esquema** | Variable por EventID (20+ tipos) | Fijo (39 campos) |
| **Campos temporales** | 1 (`UtcTime` → `timestamp`) | 3 (`timestamp`, `event_start`, `event_end`) |
| **Correcciones de tipo** | GUIDs, enteros | Puertos float→int, arrays |
| **Análisis integrado** | Estadísticas básicas | EDA completo (protocolos, puertos, volumen) |
| **Arquitectura** | ThreadPoolExecutor | ThreadPoolExecutor (idéntica) |

---

## Parte C: Limpieza de Calidad de Datos Sysmon (Script 4)

### El problema: Violaciones de ProcessGuid

Después de generar el CSV de Sysmon con el Script 2, puede haber problemas de calidad que deben corregirse antes de avanzar en el pipeline. El más crítico es la **violación de ProcessGuid**.

En Sysmon, el `ProcessGuid` es un identificador único que debería identificar de forma unívoca un proceso. La regla fundamental es:

> **Un ProcessGuid debe corresponder a exactamente un ProcessId y exactamente una Image (ruta del ejecutable).**

Sin embargo, en la práctica encontramos dos tipos de violaciones:

| Tipo de violación | Descripción | Ejemplo |
|-------------------|-------------|---------|
| **PID violation** | Un GUID mapea a múltiples PIDs | `{GUID-abc}` → PID 1234, PID 5678 |
| **Image violation** | Un GUID mapea a múltiples rutas de ejecutable | `{GUID-xyz}` → `C:\Windows\cmd.exe`, `\\?\C:\Windows\cmd.exe` |

Las violaciones de Image son frecuentemente causadas por el prefijo `\\?\` que Windows usa para rutas extendidas. Esto crea **falsos positivos** donde `C:\Windows\cmd.exe` y `\\?\C:\Windows\cmd.exe` son realmente la misma imagen.

### Arquitectura del pipeline de limpieza

El Script 4 es un **orquestador** que ejecuta 5 sub-scripts en secuencia:

```
┌─────────────────────────────────────────────────────────────┐
│            Script 4: Pipeline de Limpieza                    │
│                                                              │
│  Paso 1  ┌──────────────────────────────────┐               │
│  ───────►│ find_processguid_pid_violations   │               │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 2  ┌──────────────────────────────────┐               │
│  ───────►│ find_processguid_image_violations │               │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 3  ┌──────────────────────────────────┐               │
│  ───────►│ normalize_path_duplicates         │  ← \\?\ fix  │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 4  ┌──────────────────────────────────┐               │
│  ───────►│ extract_violation_events          │               │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 5  ┌──────────────────────────────────┐               │
│   (opt)  │ Manual editing (LibreOffice Calc) │  ← Humano    │
│          └──────────────┬───────────────────┘               │
│                         ▼                                    │
│  Paso 6  ┌──────────────────────────────────┐               │
│  ───────►│ apply_violation_fixes             │               │
│          └──────────────────────────────────┘               │
│                                                              │
│  Input:  sysmon-run-XX.csv                                   │
│  Output: sysmon-run-XX.csv (corregido in-place)              │
└─────────────────────────────────────────────────────────────┘
```

### Paso 1-2: Detección de violaciones

Los dos primeros pasos analizan el CSV de Sysmon buscando GUIDs que violen la regla de unicidad:

```python
def detect_violations(run_id) -> bool:
    """
    Ejecuta los scripts de detección de violaciones PID e Image.
    Genera archivos CSV con las violaciones encontradas en exploration/violations/.
    """
    # Paso 1: Detectar violaciones de PID
    run_command(
        [sys.executable, str(QUALITY_DIR / "find_processguid_pid_violations.py"),
         "--run-id", run_id],
        "Detecting ProcessGuid-PID violations"
    )

    # Paso 2: Detectar violaciones de Image
    run_command(
        [sys.executable, str(QUALITY_DIR / "find_processguid_image_violations.py"),
         "--run-id", run_id],
        "Detecting ProcessGuid-Image violations"
    )

    return True
```

**Archivos generados:**
```
exploration/violations/
├── processguid_pid_violations_runXX.csv
└── processguid_image_violations_runXX.csv
```

### Paso 3: Normalización de rutas

La normalización elimina falsos positivos causados por el prefijo de rutas extendidas de Windows:

```python
def normalize_violations(run_id, skip_normalization) -> bool:
    """
    Normaliza duplicados causados por el prefijo '\\\\?\\' de Windows.

    Ejemplo:
    - Antes: {GUID} → ['C:\\Windows\\cmd.exe', '\\\\?\\C:\\Windows\\cmd.exe']
    - Después: {GUID} → ['C:\\Windows\\cmd.exe']  (ya no es violación)
    """
    if skip_normalization:
        return True

    run_command(
        [sys.executable, str(QUALITY_DIR / "normalize_path_duplicates.py"),
         "--run-id", run_id],
        "Normalizing path duplicates"
    )
    return True
```

### Paso 4-5: Extracción y edición manual

Las violaciones que no son falsos positivos se extraen a un archivo CSV separado para revisión manual:

```python
def extract_violations(run_id) -> bool:
    """
    Extrae los eventos con violaciones a un archivo separado para edición.
    """
    run_command(
        [sys.executable, str(QUALITY_DIR / "extract_violation_events.py"),
         "--run-id", run_id],
        "Extracting violation events"
    )
    return True


def manual_editing_pause(violations_file, auto_skip) -> bool:
    """
    Pausa interactiva para revisión manual de las violaciones.
    Opcionalmente abre LibreOffice Calc para editar el CSV.

    El archivo contiene columnas adicionales:
    - _original_row_index: Posición en el CSV original (para trazabilidad)
    - _row_hash: Hash del registro original (para validación de integridad)
    """
    if auto_skip:
        return True

    print(f"\nViolations file ready for manual review: {violations_file}")
    response = input("Open in LibreOffice Calc? [y/N]: ")
    if response.lower() == 'y':
        subprocess.run(['libreoffice', '--calc', str(violations_file)])

    input("Press Enter when done editing...")
    return True
```

**Puntos clave:**
- Este paso introduce un componente **human-in-the-loop**: el analista revisa las violaciones y decide cómo corregirlas (ej: asignar el PID correcto, eliminar registros duplicados).
- Las columnas `_original_row_index` y `_row_hash` permiten rastrear cada corrección hasta su registro original en el CSV.

### Paso 6: Aplicación de correcciones

Finalmente, las correcciones manuales se aplican al CSV original:

```python
def apply_fixes(run_id, dry_run, verbose) -> bool:
    """
    Aplica las correcciones del archivo de violaciones al CSV original.

    Args:
        run_id: Identificador del run
        dry_run: Si True, solo muestra los cambios sin aplicarlos
        verbose: Si True, muestra cada cambio individual
    """
    cmd = [sys.executable, str(QUALITY_DIR / "apply_violation_fixes.py"),
           "--run-id", run_id]

    if dry_run:
        cmd.append("--dry-run")
    if verbose:
        cmd.append("--verbose")

    run_command(cmd, "Applying violation fixes")
    return True
```

### Uso del script

```bash
# Flujo completo: detectar, normalizar, extraer, editar, aplicar
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05

# Solo detección (sin correcciones)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --detect-only

# Solo aplicar correcciones (si ya se editó el archivo de violaciones)
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --apply-only

# Vista previa de cambios sin aplicar
python 4_sysmon_data_cleaner.py --apt-type apt-1 --run-id 05 --dry-run --verbose
```

---

## Actividad Práctica

### Ejercicio 1: Análisis de Decisiones de Diseño

Responde las siguientes preguntas basándote en el análisis de los tres scripts:

1. **¿Por qué los Scripts 2 y 3 usan `ThreadPoolExecutor` en lugar de `ProcessPoolExecutor`?** Considera qué tipo de operación domina el procesamiento (I/O vs CPU) y las implicaciones del GIL de Python.

2. **¿Qué ocurriría si el Script 3 no agrupara por `flow_id` al calcular volúmenes de tráfico?** Explica el concepto de doble conteo en el contexto de flujos de red.

3. **¿Por qué el Script 2 convierte `UtcTime` a epoch milliseconds en lugar de mantener el formato datetime?** Piensa en las etapas posteriores del pipeline (correlación temporal Script 5).

### Ejercicio 2: Mapeo de EventIDs a Tácticas

Usando la tabla de EventIDs de Sysmon presentada en esta sección, mapea los siguientes escenarios de ataque APT al EventID que los detectaría:

| Escenario de ataque | EventID esperado |
|---------------------|-----------------|
| El atacante ejecuta `mimikatz.exe` para extraer credenciales | ? |
| Se establece un túnel DNS hacia un servidor C2 | ? |
| Se descarga un payload malicioso al disco | ? |
| Un proceso accede a la memoria de LSASS | ? |
| El atacante borra archivos para cubrir sus huellas | ? |

### Ejercicio 3: Violaciones de ProcessGuid

Dado el siguiente fragmento de datos de Sysmon:

| ProcessGuid | ProcessId | Image |
|-------------|-----------|-------|
| {ABC-123} | 4520 | `C:\Windows\System32\cmd.exe` |
| {ABC-123} | 4520 | `\\?\C:\Windows\System32\cmd.exe` |
| {DEF-456} | 1234 | `C:\Tools\nc.exe` |
| {DEF-456} | 5678 | `C:\Tools\nc.exe` |

1. **¿Cuántas violaciones hay y de qué tipo?** Identifica si son violaciones PID, Image, o ambas.
2. **¿Cuál de ellas se resolvería automáticamente** con la normalización del prefijo `\\?\`?
3. **¿Cuál requiere intervención manual?** ¿Qué información adicional necesitarías para decidir la corrección?

### Resultado Esperado

Al finalizar esta sección, deberías comprender:

- El flujo completo de transformación de datos JSONL a CSV para ambos dominios (Sysmon y NetFlow).
- Las diferencias arquitecturales entre parsear XML embebido (Sysmon) y aplanar JSON anidado (NetFlow).
- Por qué el procesamiento multi-hilo es necesario para archivos de cientos de miles de eventos.
- La importancia de la estandarización temporal (epoch milliseconds) para la correlación entre dominios.
- Cómo detectar y corregir violaciones de integridad de ProcessGuid en datos de Sysmon.
- El rol del componente human-in-the-loop en el pipeline de calidad de datos.
