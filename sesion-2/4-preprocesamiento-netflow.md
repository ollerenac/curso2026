# Preprocesamiento NetFlow: De JSONL a CSV (Script 3)

**Duración**: 30 minutos

```{admonition} Script de trabajo
:class: note

**Script**: `scripts/pipeline/3_netflow_csv_creator.py`
```

## Contexto

En las secciones anteriores convertimos los datos Sysmon de JSONL a CSV (sección 1), analizamos la calidad del CSV resultante (sección 2), y limpiamos las violaciones de ProcessGuid detectadas (sección 3). Ahora aplicamos la misma conversión JSONL → CSV al dominio NetFlow, donde el reto es fundamentalmente diferente: no hay XML, pero sí una **jerarquía JSON de hasta 3 niveles** que debe aplanarse a un CSV de 39 columnas.

```
Pipeline de preprocesamiento (contexto):

  Script 2 (Sysmon)  ── ✅ Sección 1: Conversión JSONL → CSV
  Notebook 2c        ── ✅ Sección 2: Análisis de calidad del CSV
  Script 4 (Limpieza)── ✅ Sección 3: Limpieza de violaciones
  Script 3 (NetFlow)  ── ◄── Esta sección
```

## Conversión de NetFlow JSONL a CSV

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
- La estandarización a epoch milliseconds permite la **correlación temporal** entre Sysmon y NetFlow en el Script 5 (Sesión 3). Ambos dominios comparten la misma escala temporal.
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

## Actividad Práctica

### Ejercicio 1: Decisiones de Diseño del Conversor NetFlow

1. **¿Qué ocurriría si el Script 3 no agrupara por `flow_id` al calcular volúmenes de tráfico?** Explica el concepto de doble conteo en el contexto de flujos de red.

2. **NetFlow tiene 3 campos temporales (`@timestamp`, `event.start`, `event.end`) mientras que Sysmon tiene 1 (`UtcTime`).** ¿Por qué un flujo de red necesita tres timestamps? ¿Cuál usarías para correlacionar con Sysmon y por qué?

3. **La función `get_nested_value` devuelve `None` cuando una ruta no existe.** ¿Qué alternativas de diseño existían (lanzar excepción, valor por defecto configurable, logging)? ¿Por qué `None` es la mejor opción para este caso de uso?

4. **Los puertos llegan como `float` desde Elasticsearch (`443.0`).** ¿Por qué ocurre esto? Pista: piensa en cómo Elasticsearch almacena campos numéricos que pueden tener valores nulos.

### Resultado Esperado

Al finalizar esta sección, deberías comprender:

- Cómo aplanar una jerarquía JSON de múltiples niveles a un CSV tabular usando notación de puntos.
- Las diferencias de diseño entre el conversor Sysmon (esquema variable por EventID) y el conversor NetFlow (esquema fijo de 39 columnas).
- La importancia de la estandarización temporal a epoch milliseconds para habilitar la correlación cruzada entre dominios.
- Por qué el agrupamiento por `flow_id` es necesario para evitar doble conteo en métricas de tráfico.

En la siguiente sección analizaremos la **calidad del CSV de Sysmon** resultante, evaluando distribuciones de eventos, patrones temporales, relaciones entre procesos, y readiness para algoritmos de análisis causal.
