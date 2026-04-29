# Preprocesamiento Sysmon: De JSONL a CSV (Scripts 2 y 4)

**Duración**: 60 minutos

```{admonition} Script de trabajo
:class: note

**Script principal**: `7_sysmon_csv_creator.py` (copia local de `2_sysmon_csv_creator.py`)

**Script de limpieza**: `4_sysmon_data_cleaner.py` (pipeline fullapt2025 — cubierto en sección 9)

**Sub-scripts de calidad**: `fullapt2025/scripts/pipeline/quality/`
```

```{admonition} Antes de continuar — haz una predicción
:class: note

Tienes un archivo JSONL de 2.1 GB con 363,657 eventos Sysmon. Necesitas convertirlo a CSV. Antes de ver cómo lo resuelve el script:

1. ¿Podrías simplemente hacer `pd.read_json("sysmon.jsonl", lines=True)` y obtener un CSV usable? ¿Qué obstáculo principal lo impide?
2. Con 400,000+ eventos, ¿procesarías el archivo entero de una vez o lo dividirías? Si lo divides, ¿cómo combinarías los resultados?
3. Sysmon tiene 21 tipos de eventos con campos diferentes. ¿El CSV resultante tendría columnas diferentes por tipo, o **todas** las columnas posibles con muchos valores vacíos?

Anota tus respuestas y compáralas con las decisiones del script a lo largo de esta sección.
```

## Contexto: ¿Por qué necesitamos CSV?

En las secciones anteriores exploramos los raw data en formato JSONL y validamos su consistencia estructural. Ahora debemos transformarlos en un formato que permita dos cosas: **análisis exploratorio eficiente** (filtrado, agrupación, estadísticas) y **alimentar algoritmos de machine learning** (que esperan datos tabulares). El formato JSONL no sirve para ninguna de las dos — cada registro es un documento anidado que requiere parsing individual.

Recordemos el estado actual de nuestros datos:

```
dataset/run-XX-apt-Y/
├── ds-logs-windows-sysmon-*.jsonl    ← Eventos Sysmon (XML embebido en JSON)
└── ds-logs-network_traffic-*.jsonl   ← Flujos NetFlow (JSON anidado)
```

El objetivo de esta sección es producir:

```
dataset/run-XX-apt-Y/
├── 02_sysmon-run-XX.csv                    ← CSV tabular con todos los eventos Sysmon
├── 03_netflow-run-XX.csv                   ← CSV tabular con todos los flujos de red
├── 02_log-sysmon-jsonl-to-csv-run-XX.json ← Log de procesamiento Sysmon
└── 03_log-netflow-jsonl-to-csv-run-XX.json ← Log de procesamiento NetFlow
```

### Decisión de diseño: ¿un CSV por EventID o uno unificado?

Sysmon tiene 21 tipos de eventos, cada uno con entre 3 y 16 campos diferentes. Podríamos generar un CSV por EventID (21 archivos densos, sin columnas vacías) o un CSV unificado (un solo archivo con la unión de todos los campos, donde ~80% de las celdas serán `NaN`). ¿Cuál es mejor?

| Aspecto | CSV por EventID (21 archivos) | CSV unificado (50 columnas) |
|---------|-------------------------------|---------------------------|
| **Columnas por archivo** | 5–18 (según EventID) | 50 (fijas) |
| **NaN estructurales** | ~0% | ~80% de las celdas |
| **Análisis cruzado** | Requiere joins por ProcessGuid | Directo (un solo DataFrame) |
| **Lifecycle tracing** | Multi-join entre 21 archivos | `df[df.ProcessGuid == guid]` |

La respuesta depende del **uso posterior** de los datos:

- **Si el objetivo es entrenar un modelo por tipo de evento** (ej: detectar anomalías solo en conexiones de red), un CSV por EventID elimina toda la dispersión y es más limpio.
- **Si el objetivo es trazar cadenas causales entre tipos de eventos** — que es exactamente lo que hacen los Scripts 7 y 8 del pipeline (etiquetado y trazado de ciclo de vida de ataques) — necesitamos todos los eventos en un solo DataFrame para poder seguir un `ProcessGuid` a través de: creación de proceso (EID 1) → conexión de red (EID 3) → creación de archivo (EID 11) → eliminación de archivo (EID 23).

El script elige la **unión de esquemas** porque el pipeline completo necesita análisis cruzado entre EventIDs.

El coste de esta decisión es evidente: ~80% de las celdas del CSV resultante serán `NaN`. ¿Es esto un problema para machine learning? En la práctica, no — por tres razones:

1. **Los NaN son deterministas, no aleatorios**: cada NaN se explica por el EventID de la fila. Filtrar `df[df.EventID == 3]` antes de analizar tráfico de red produce un subset con cero NaN en las columnas de red. La dispersión desaparece al segmentar por tipo de evento.
2. **Los frameworks de ML modernos lo manejan nativamente**: XGBoost y LightGBM tratan NaN como una dirección de split aprendible, y las matrices dispersas (`scipy.sparse`) almacenan solo los valores no nulos — el ~80% de celdas vacías no consume memoria.
3. **Es el estándar de la industria**: los datasets de ciberseguridad de referencia (CICIDS, UNSW-NB15) y las herramientas SIEM (Splunk, Elastic) usan esquemas unificados con dispersión estructural (*structural sparsity*: celdas vacías que no son datos faltantes sino consecuencia predecible del diseño — cada EventID solo tiene sentido en sus propias columnas).

### ¿Por qué no usar pandas directamente?

Dado que elegimos un CSV unificado, una primera aproximación sería simplemente cargar el JSONL con pandas:

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

El preprocesamiento se organiza en **dos líneas de trabajo independientes**, una por dominio de telemetría. Dentro de la línea Sysmon, los scripts son secuenciales (el Script 4 corrige el CSV generado por el Script 2):

```
┌──────────────────────────────────────────────────────────────┐
│                      Preprocesamiento                        │
│                                                              │
│   Línea Sysmon                        Línea NetFlow          │
│   ─────────────                       ──────────────         │
│                                                              │
│   ┌──────────────┐                    ┌──────────────┐       │
│   │  Script 2    │                    │  Script 3    │       │
│   │  Sysmon      │                    │  NetFlow     │       │
│   │  JSONL → CSV │                    │  JSONL → CSV │       │
│   └──────┬───────┘                    └──────┬───────┘       │
│          │                                   │               │
│          ▼                                   ▼               │
│   sysmon-run-XX.csv                   netflow-run-XX.csv     │
│          │                            (resultado final)      │
│          ▼                                                   │
│   ┌──────────────┐                                           │
│   │  Script 4    │                                           │
│   │  Limpieza    │                                           │
│   │  de Calidad  │                                           │
│   └──────┬───────┘                                           │
│          │                                                   │
│          ▼                                                   │
│   sysmon-run-XX.csv                                          │
│   (corregido)                                                │
│                                                              │
│   ◄──── Secuencial ────►            ◄── Independiente ──►    │
└──────────────────────────────────────────────────────────────┘
```

Las dos líneas son **independientes** y pueden ejecutarse en paralelo. Dentro de la línea Sysmon, el Script 4 debe ejecutarse **después** del Script 2, ya que corrige problemas de calidad en el CSV generado.

---

## Conversión de Sysmon JSONL a CSV (Script 2)

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
┌────────────────────────────────────────────────────────────────────────────────┐
│                  SysmonCSVCreator                                              │
│                                                                                │
│  Archivo JSONL                                                                 │
│       │                                                                        │
│       ▼                                                                        │
│  read_jsonl_in_chunks()                                                        │
│       │                                                                        │
│       ├──► Chunk 1 ──►  ThreadPoolExecutor ──┐                                 │
│       ├──► Chunk 2 ──►   (process_chunk)   ──┤                                 │
│       ├──► Chunk 3 ──►                     ──┤                                 │
│       └──► Chunk N ──►                     ──┘                                 │
│                          Cada hilo:                                            │
│                          json.loads → parse_sysmon_event → _build_event_record │
│                                              │                                 │
│                                    merge_chunk_stats()                         │
│                                              │                                 │
│                                              ▼                                 │
│                                     pd.DataFrame                               │
│                                              │                                 │
│                                    clean_dataframe()                           │
│                                              │                                 │
│                                              ▼                                 │
│                                        CSV final                               │
└────────────────────────────────────────────────────────────────────────────────┘
```

### Lectura y partición en chunks

Siguiendo el diagrama de arquitectura, el primer paso del pipeline es `read_jsonl_in_chunks`: leer el archivo JSONL completo y dividirlo en bloques independientes que los hilos procesarán en paralelo. El script usa una lectura **en streaming** (línea por línea) en lugar de cargar todo el archivo en memoria:

```python
def read_jsonl_in_chunks(self, jsonl_path: str) -> List[List[str]]:
    """
    Lee un archivo JSONL en streaming y lo divide en chunks.

    Args:
        jsonl_path: Ruta al archivo JSONL de entrada

    Returns:
        Lista de chunks, donde cada chunk es una lista de líneas JSON
    """
    chunks = []
    current_chunk = []

    with open(jsonl_path, 'r') as f:
        for line_number, line in enumerate(f, 1):
            current_chunk.append(line.strip())

            if len(current_chunk) >= self.chunk_size:
                chunks.append(current_chunk)
                current_chunk = []

            # Reporte de progreso cada 100,000 líneas
            if line_number % 100000 == 0:
                self.logger.info(f"Read {line_number:,} lines, created {len(chunks)} chunks")

        # Agregar líneas restantes
        if current_chunk:
            chunks.append(current_chunk)

    return chunks
```

**Puntos clave:**
- El `chunk_size` por defecto es **10,000 líneas** por bloque. Este valor, junto con otros parámetros como `max_workers`, se puede modificar mediante un archivo de configuración YAML opcional que se pasa al script con `--config config.yaml` (ver Apéndice: Configuración del Pipeline).
- La lectura en streaming (`for line in f`) evita cargar todo el archivo en memoria — crítico para archivos JSONL de cientos de miles de eventos.
- Al dividir en chunks, cada hilo de ejecución procesa un bloque independiente sin compartir estado.
- El número de workers se auto-detecta con `multiprocessing.cpu_count()` o se configura manualmente en el mismo archivo YAML.

### Parsing de eventos Sysmon: de XML a diccionario

Una vez que tenemos los chunks, cada hilo debe procesar sus líneas individualmente. Pero antes de poder extraer campos, el XML embebido puede contener caracteres inválidos (bytes corruptos de logs de Windows). Por eso el parsing se divide en dos pasos: primero **sanitizar** el XML para hacerlo parseable, y luego **extraer** los campos estructurados:

```python
def sanitize_xml(self, xml_str: str) -> str:
    """
    Limpia caracteres inválidos y repara estructura XML corrupta.
    Utiliza BeautifulSoup como parser tolerante.
    """
    # Eliminar caracteres no imprimibles y no-ASCII
    cleaned = ''.join(c for c in xml_str if 31 < ord(c) < 127 or c in '\t\n\r')
    # Reparar con BeautifulSoup y retornar XML limpio
    return BeautifulSoup(cleaned, "xml").prettify()
```

La sanitización elimina **todos los caracteres fuera del rango ASCII imprimible** (códigos 32-126) y los caracteres de control, excepto tabuladores y saltos de línea. Esto es más agresivo que un simple filtrado de caracteres de control — protege contra cualquier byte no estándar que pudiera romper el parser XML.

Una vez que el XML está limpio, necesitamos entender su estructura para saber **qué extraer y de dónde**. Un evento Sysmon en XML de Windows Event Log tiene dos bloques principales dentro del elemento raíz `<Event>`:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">

  <System>                              ← Bloque 1: metadatos del evento
    <EventID>1</EventID>                   Valor directo como texto del elemento
    <Computer>PC1.domain.local</Computer>  Valor directo como texto del elemento
    <TimeCreated SystemTime="..." />
    ...
  </System>

  <EventData>                           ← Bloque 2: campos específicos de Sysmon
    <Data Name="UtcTime">2025-01-29 04:25:12.345</Data>
    <Data Name="ProcessGuid">{abc-123...}</Data>
    <Data Name="Image">C:\Windows\cmd.exe</Data>
    <Data Name="CommandLine">cmd /c whoami</Data>
    ...                                    Cada campo es un <Data Name="X">valor</Data>
  </EventData>

</Event>
```

La diferencia es fundamental para la extracción:

- **`<System>`** contiene elementos con **nombres fijos** (`<EventID>`, `<Computer>`). El valor se obtiene directamente del texto del elemento: `element.text` → `"1"`, `"PC1.domain.local"`.
- **`<EventData>`** contiene una **lista de elementos `<Data>`**, todos con el mismo tag pero diferenciados por el atributo `Name`. El valor se obtiene del texto, pero la clave se obtiene del atributo: `data.get('Name')` → `"Image"`, `data.text` → `"C:\Windows\cmd.exe"`.

Esta diferencia explica por qué la función de parsing tiene dos bloques separados de extracción — uno navega por nombre de elemento fijo, el otro itera sobre una lista genérica de pares nombre-valor:

```python
def parse_sysmon_event(self, xml_str: str) -> Tuple[Optional[int], Optional[str], Dict]:
    """
    Parsea un evento Sysmon desde XML a componentes estructurados.

    Args:
        xml_str: Cadena XML del campo event.original

    Returns:
        Tupla de (EventID, Computer hostname en minúsculas, diccionario de campos EventData)
    """
    try:
        clean_xml = self.sanitize_xml(xml_str)
        namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(clean_xml)

        # Extraer EventID y Computer del bloque <System>
        system = root.find('ns:System', namespaces)
        if not system:
            return None, None, {}

        event_id_elem = system.find('ns:EventID', namespaces)
        computer_elem = system.find('ns:Computer', namespaces)

        event_id = int(event_id_elem.text) if event_id_elem is not None else None
        computer = computer_elem.text.lower() if computer_elem is not None else None

        # Extraer todos los campos de <EventData>
        event_data = root.find('ns:EventData', namespaces)
        fields = {}
        if event_data:
            for data in event_data.findall('ns:Data', namespaces):
                name = data.get('Name')
                fields[name] = data.text if data.text else None

        return event_id, computer, fields

    except Exception as e:
        # Registrar XML problemático para depuración
        with open('bad_xml_samples.txt', 'a') as bad_xml:
            bad_xml.write(f"Error: {str(e)}\nXML: {xml_str[:500]}...\n" + "-"*50 + "\n")
        return None, None, {}
```

**Puntos clave del código:**
- **Namespace obligatorio**: Todas las llamadas a `find()` y `findall()` requieren el prefijo `ns:` porque el XML de Windows Event Log declara el namespace `http://schemas.microsoft.com/win/2004/08/events/event`. Sin el diccionario `namespaces`, las búsquedas no encontrarían ningún elemento.
- **`<System>` → acceso directo**: `system.find('ns:EventID')` localiza un elemento con nombre fijo. Su valor se lee con `.text` y se convierte a entero.
- **`<EventData>` → iteración genérica**: `event_data.findall('ns:Data')` devuelve *todos* los elementos `<Data>` sin importar cuántos haya. El nombre del campo se obtiene del atributo `Name` con `.get('Name')`, y el valor del texto del elemento.
- **Computer en minúsculas**: El hostname se normaliza con `.lower()`. Esto explica por qué en el CSV los hosts aparecen como `waterfalls.boombox.local` en lugar de `WATERFALLS.boombox.local` del JSONL original.
- **Preservación de nulos**: Los campos cuyo texto es `None` o vacío se almacenan como `None` — no se descartan. Esto permite distinguir entre "campo presente pero vacío" y "campo ausente".
- **Logging de errores**: Los eventos con XML que falla el parsing se registran en `bad_xml_samples.txt` para depuración posterior, en lugar de abortar la ejecución.

### Esquema por EventID

La función `parse_sysmon_event` nos devuelve el `EventID`, el `Computer`, y un diccionario con **todos** los campos de `EventData` — pero no todos esos campos son relevantes para cada tipo de evento. ¿Cómo sabe el script qué campos conservar? Mediante un mapa de esquema que define exactamente qué campos extraer para cada EventID (para una descripción detallada de cada campo por EventID, ver el [Apéndice: Event Data Collection](../appendices/event-data-collection.md#sysmon-events-and-fields-per-event)):

```python
self.fields_per_eventid = {
    1:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'CommandLine',
         'CurrentDirectory', 'User', 'Hashes', 'ParentProcessGuid',
         'ParentProcessId', 'ParentImage', 'ParentCommandLine'],
    2:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename',
         'CreationUtcTime', 'PreviousCreationUtcTime', 'User'],
    3:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol',
         'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort',
         'SourcePortName', 'DestinationIsIpv6', 'DestinationIp',
         'DestinationHostname', 'DestinationPort', 'DestinationPortName'],
    5:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User'],
    6:  ['UtcTime', 'ImageLoaded', 'Hashes'],
    7:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ImageLoaded',
         'OriginalFileName', 'Hashes', 'User'],
    8:  ['UtcTime', 'SourceProcessGuid', 'SourceProcessId', 'SourceImage',
         'TargetProcessGuid', 'TargetProcessId', 'TargetImage',
         'NewThreadId', 'SourceUser', 'TargetUser'],
    9:  ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'Device', 'User'],
    10: ['UtcTime', 'SourceProcessGUID', 'SourceProcessId', 'SourceImage',
         'TargetProcessGUID', 'TargetProcessId', 'TargetImage',
         'SourceThreadId', 'SourceUser', 'TargetUser'],
    11: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename',
         'CreationUtcTime', 'User'],
    12: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image',
         'TargetObject', 'User'],
    13: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image',
         'TargetObject', 'User'],
    14: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image',
         'TargetObject', 'User'],
    15: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename',
         'CreationUtcTime', 'Hash', 'User'],
    16: ['UtcTime', 'Configuration', 'ConfigurationFileHash', 'User'],
    17: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName',
         'Image', 'User'],
    18: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName',
         'Image', 'User'],
    22: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'QueryName',
         'QueryStatus', 'QueryResults', 'User'],
    23: ['UtcTime', 'ProcessGuid', 'ProcessId', 'User', 'Image',
         'TargetFilename', 'Hashes'],
    24: ['UtcTime', 'ProcessGuid', 'ProcessId', 'User', 'Image', 'Hashes'],
    25: ['UtcTime', 'ProcessGuid', 'ProcessId', 'User', 'Image'],
}
```

Nótese que la complejidad varía enormemente: desde 3 campos (EID 6 — Driver Loaded) hasta 16 campos (EID 3 — Network Connection). Los EventIDs 12, 13, 14 (operaciones de registro) comparten exactamente la misma estructura, al igual que 17 y 18 (operaciones de pipes).

Los EventIDs más relevantes para la detección de APTs son:

| EventID | Nombre | Campos | Relevancia para APT |
|---------|--------|--------|---------------------|
| 1 | Process Creation | 12 | Ejecución de herramientas maliciosas, shells, scripts |
| 3 | Network Connection | 16 | Comunicación C2, exfiltración, movimiento lateral |
| 7 | Image Loaded | 8 | DLL injection, side-loading |
| 8 | Create Remote Thread | 10 | Inyección de código entre procesos |
| 10 | Process Access | 10 | Credential dumping (LSASS), injection |
| 11 | File Create | 7 | Descarga de payloads, creación de archivos maliciosos |
| 23 | File Delete | 7 | Anti-forensics, limpieza de huellas |

Algunos de estos conceptos merecen una aclaración porque son fundamentales para entender por qué estos EventIDs caracterizan el comportamiento de un proceso:

- **Image / Image Loaded (EID 7)**: En el contexto de Windows, una *image* es cualquier archivo ejecutable cargado en memoria — no solo `.exe`, sino también librerías dinámicas (`.dll`), drivers (`.sys`) y otros binarios. Cuando un proceso carga una DLL, Sysmon registra un evento EID 7 con el campo `ImageLoaded` indicando la ruta de la librería. Esto es crítico para detectar técnicas como *DLL side-loading* (donde el atacante coloca una DLL maliciosa en una ubicación donde un proceso legítimo la cargará automáticamente) o *DLL injection* (donde se fuerza a un proceso a cargar una librería que no debería).

- **Create Remote Thread (EID 8)**: Un *thread* (hilo de ejecución) es la unidad mínima de código que el sistema operativo programa para ejecución dentro de un proceso. Un proceso puede tener múltiples threads ejecutándose simultáneamente. Lo normal es que un proceso cree threads *dentro de sí mismo*. Un **remote thread** es un thread que un proceso crea *dentro de otro proceso* — esto es intrínsecamente sospechoso porque es la base de técnicas de inyección de código: el atacante usa un proceso legítimo (ej: `explorer.exe`) para ejecutar código malicioso creando un thread remoto que apunta a código inyectado previamente en la memoria del proceso víctima.

- **Process Access (EID 10)**: Este evento se registra cuando un proceso abre un *handle* (descriptor de acceso) a otro proceso con permisos específicos (lectura de memoria, escritura, etc.). En operación normal, pocos procesos necesitan acceder a la memoria de otros. La razón principal por la que este EventID es crítico es la técnica de *credential dumping*: herramientas como `mimikatz` acceden al proceso `lsass.exe` (Local Security Authority Subsystem Service) para extraer credenciales almacenadas en memoria. Cada vez que un proceso accede a LSASS, Sysmon lo registra con EID 10, identificando quién (`SourceImage`) accedió a quién (`TargetImage`).

Estos tres EventIDs, junto con EID 1 (Process Creation) y EID 3 (Network Connection), forman el núcleo de la telemetría necesaria para reconstruir el comportamiento completo de un proceso: qué ejecutó, qué librerías cargó, a qué otros procesos accedió, qué threads inyectó, y con qué IPs se comunicó.

### Tipos de datos y columnas especiales

El esquema nos dice **qué campos** extraer, pero no **cómo** convertirlos. Algunos campos requieren transformaciones de tipo: los PIDs y puertos deben ser enteros (no strings), y los GUIDs deben limpiarse de llaves y whitespace. El script define conjuntos de columnas que requieren tratamiento especial:

```python
self.integer_columns = {
    'ProcessId', 'SourcePort', 'DestinationPort', 'SourceProcessId',
    'ParentProcessId', 'SourceThreadId', 'TargetProcessId'
}

self.guid_columns = {
    'ProcessGuid', 'SourceProcessGUID', 'TargetProcessGUID', 'ParentProcessGuid'
}
```

Las funciones de conversión manejan valores nulos y formatos inesperados:

```python
def safe_int_conversion(self, value) -> Optional[int]:
    """Convierte un valor a entero de forma segura, manejando NaN y whitespace."""
    if value is None or pd.isna(value):
        return None
    try:
        cleaned_value = str(value).strip()
        if not cleaned_value:
            return None
        return int(float(cleaned_value))
    except (ValueError, TypeError):
        return None

def clean_guid(self, value) -> Optional[str]:
    """Elimina llaves y whitespace de GUIDs, retornando solo el identificador."""
    if value is None or pd.isna(value):
        return None
    try:
        cleaned = str(value).strip().strip('{}')
        return cleaned if cleaned else None
    except (ValueError, TypeError):
        return None
```

**Puntos clave:**
- `safe_int_conversion` pasa por `float` antes de `int` para manejar valores como `"1234.0"` que llegan desde Elasticsearch.
- `clean_guid` elimina las llaves (`{...}`) de los GUIDs de Windows. Por ejemplo, `{3fc4fefd-de08-67da-0c00-000000004900}` se convierte en `3fc4fefd-de08-67da-0c00-000000004900`.

### Construcción de registros tabulares

Ahora podemos combinar todas las piezas anteriores. Para cada evento, `_build_event_record` realiza el flujo completo: consulta `fields_per_eventid` para obtener el esquema, extrae los valores del diccionario de campos XML, aplica `safe_int_conversion` o `clean_guid` según el tipo de columna, y produce un diccionario plano listo para insertar en el DataFrame.

Un caso especial importante es el **EventID 8** (Create Remote Thread), donde los nombres de campo en el XML difieren en capitalización de los nombres de columna del CSV:

```python
def _build_event_record(self, event_id: int, computer: str,
                        fields: Dict, chunk_stats: Dict) -> Optional[Dict]:
    """
    Construye un registro tabular a partir de los campos parseados.

    Returns:
        Diccionario plano listo para insertar en DataFrame, o None
    """
    schema = self.fields_per_eventid.get(event_id)
    if schema is None:
        return None

    record = {'EventID': event_id, 'Computer': computer}

    for field_name in schema:
        # Caso especial: EventID 8 usa 'SourceProcessGuid' en el XML
        # pero la columna del CSV es 'SourceProcessGUID' (mayúsculas)
        if event_id == 8:
            if field_name == 'SourceProcessGuid':
                record['SourceProcessGUID'] = self.clean_guid(fields.get(field_name))
                continue
            elif field_name == 'TargetProcessGuid':
                record['TargetProcessGUID'] = self.clean_guid(fields.get(field_name))
                continue

        # Procesamiento normal con conversión de tipos
        value = fields.get(field_name)
        if field_name in self.integer_columns:
            value = self.safe_int_conversion(value)
        elif field_name in self.guid_columns:
            value = self.clean_guid(value)
        elif value is not None:
            value = str(value).strip() or None

        record[field_name] = value

    return record
```

**Puntos clave:**
- **Esquema unión**: El CSV final contiene la **unión** de todos los campos de los 21 EventIDs (50 columnas totales). Un evento de tipo 1 (Process Creation) tendrá valores `NaN` en los campos específicos de tipo 3 (Network Connection) y viceversa.
- **Mapeo de case EID 8**: En el esquema, EventID 8 define `SourceProcessGuid` y `TargetProcessGuid` (minúscula), pero EventID 10 usa `SourceProcessGUID` y `TargetProcessGUID` (mayúscula). El script mapea ambos a la misma columna `SourceProcessGUID`/`TargetProcessGUID` para unificación.
- **Tracking de campos faltantes**: El script registra estadísticas de campos que no se encuentran en el XML, útil para diagnosticar problemas de calidad.

### Procesamiento multi-hilo

Hasta ahora hemos visto las piezas individuales: `read_jsonl_in_chunks` divide el archivo, `parse_sysmon_event` extrae los campos XML, `fields_per_eventid` define el esquema, y `_build_event_record` construye cada registro. La función `process_events` es el **orquestador** que las conecta: distribuye chunks entre hilos, cada hilo procesa sus eventos llamando a las funciones anteriores, y finalmente se combinan todos los resultados en un único DataFrame.

```python
def process_events(self, jsonl_path: str) -> pd.DataFrame:
    """
    Procesamiento multi-hilo del archivo JSONL completo.

    Returns:
        DataFrame con todos los eventos procesados
    """
    chunks = self.read_jsonl_in_chunks(jsonl_path)
    all_records = []
    chunk_stats_list = []

    with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
        future_to_chunk = {
            executor.submit(self.process_chunk, chunk, chunk_id): chunk_id
            for chunk_id, chunk in enumerate(chunks)
        }

        for future in as_completed(future_to_chunk):
            chunk_id = future_to_chunk[future]
            chunk_records, chunk_stats = future.result()
            all_records.extend(chunk_records)
            chunk_stats_list.append(chunk_stats)

    self.merge_chunk_stats(chunk_stats_list)

    # Guardar log estructurado JSON con estadísticas
    self._save_processing_log(jsonl_path, ...)

    return pd.DataFrame(all_records)
```

El script además genera un **log de procesamiento** en formato JSON (`02_log-sysmon-jsonl-to-csv-run-XX.json`) que incluye: tiempos de ejecución, distribución de EventIDs, campos faltantes, tasa de errores, y velocidad de procesamiento.

**Puntos clave:**
- Se utiliza `ThreadPoolExecutor` en lugar de `ProcessPoolExecutor` porque la tarea principal es I/O-bound (lectura de archivo) con algo de CPU (parsing XML). Los hilos son suficientes para este caso de uso.
- `as_completed()` procesa los resultados en orden de finalización, no de envío, lo que permite una barra de progreso más fluida.
- Las estadísticas de cada chunk se agregan de forma thread-safe usando `threading.Lock`.
- La función `merge_chunk_stats` combina contadores de EventIDs y campos faltantes de todos los hilos.

### Limpieza y optimización del DataFrame

El DataFrame que sale de `process_events` contiene todos los registros, pero aún en estado "crudo": timestamps como strings, enteros mezclados con NaN, GUIDs con llaves. La función `clean_dataframe` lo transforma en un DataFrame optimizado para ML — y, crucialmente, estandariza el formato temporal para que sea compatible con NetFlow en etapas posteriores del pipeline.

```python
def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Limpia y optimiza el DataFrame para ML.
    """
    # 1. Trim de whitespace en columnas string
    str_cols = df.select_dtypes(['object']).columns
    df[str_cols] = df[str_cols].apply(lambda x: x.str.strip())

    # 2. Reemplazar strings vacíos con None
    df.replace({'': None}, inplace=True)

    # 3. Convertir UtcTime (string) → timestamp (epoch milliseconds int64)
    if 'UtcTime' in df.columns:
        df['UtcTime'] = pd.to_datetime(df['UtcTime'], errors='coerce')

        # Ordenamiento cronológico (configurable vía YAML)
        if enable_temporal_sorting:
            df = df.sort_values('UtcTime', na_position='last').reset_index(drop=True)

        # Conversión a epoch milliseconds como entero
        df['timestamp'] = (df['UtcTime'].astype('int64') // 10**6).astype('int64')
        df = df.drop(columns=['UtcTime'])

    # 4. Optimización de tipos nullable para columnas enteras
    for col in self.integer_columns:
        if col in df.columns:
            df[col] = df[col].astype('Int64')

    # 5. GUIDs como tipo string dedicado
    for col in self.guid_columns:
        if col in df.columns:
            df[col] = df[col].astype('string')

    # 6. Columnas de baja cardinalidad como categorías
    categorical_columns = ['Computer', 'Protocol', 'EventType']
    for col in categorical_columns:
        if col in df.columns and df[col].nunique() < df.shape[0] * 0.5:
            df[col] = df[col].astype('category')

    return df
```

**Puntos clave:**
- **Limpieza de strings vacíos**: Después del trim de whitespace, los strings vacíos se reemplazan por `None`. Esto evita que campos como `RuleName: ""` se traten como valores presentes.
- **Epoch milliseconds**: Se reemplaza el campo `UtcTime` (string datetime) por `timestamp` (entero de milisegundos desde epoch), y se **elimina** la columna `UtcTime` original. Esto significa que el CSV resultante no contiene `UtcTime` — en su lugar, la columna 50 es `timestamp`. Este formato entero es más eficiente para operaciones de correlación temporal entre Sysmon y NetFlow en etapas posteriores del pipeline.
- **Timestamps inválidos**: `errors='coerce'` convierte timestamps que no se pueden parsear en `NaT` (Not a Time), que se manejan como nulos. En nuestro dataset, solo 2 de 363,657 registros tienen este problema.
- **Tipos nullable (`Int64`)**: Pandas usa `Int64` (con mayúscula) en lugar de `int64` para soportar valores `NaN` en columnas enteras — necesario porque no todos los eventos tienen todos los campos.
- **Categorías con cardinalidad**: Solo se convierten a `category` las columnas cuyo número de valores únicos es menor al 50% de las filas. Esto evita convertir columnas de alta cardinalidad donde el overhead del diccionario de categorías sería mayor que el ahorro.

### Uso del script

:::{admonition} Ejecución local — entorno y dependencias
:class: dropdown note

Antes de ejecutar el script, asegúrate de tener el entorno configurado correctamente. Desde la raíz de `curso2026/`:

**1. Activar el entorno virtual:**
```bash
source .venv/bin/activate
```

**2. Instalar dependencias** (solo la primera vez, o si faltan paquetes):
```bash
pip install -r requirements.txt
```

El `requirements.txt` incluye todas las dependencias necesarias: `pandas`, `beautifulsoup4`, `lxml`, `pyyaml`, entre otras. El script requiere específicamente `lxml` para el parser XML de BeautifulSoup — si ves el error `Couldn't find a tree builder with the features you requested: xml`, es porque `lxml` no está instalado en el entorno activo.

**3. Ejecutar desde `sesion-2/`:**
```bash
cd sesion-2

# Modo explícito — especificar entrada y salida manualmente
python3 7_sysmon_csv_creator.py \
    --input ../dataset/run-01-apt-1/ds-logs-windows-sysmon_operational-default-run-01.jsonl \
    --output ../dataset/run-01-apt-1/02_sysmon-run-01.csv

# Omitir validación (más rápido, sin backup del CSV existente)
python3 7_sysmon_csv_creator.py \
    --input ../dataset/run-01-apt-1/ds-logs-windows-sysmon_operational-default-run-01.jsonl \
    --output ../dataset/run-01-apt-1/02_sysmon-run-01.csv \
    --no-validate
```
:::

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

## Actividad Práctica

### Ejercicio 1: Decisiones de Diseño del Conversor Sysmon

1. **¿Por qué el Script 2 usa `ThreadPoolExecutor` en lugar de `ProcessPoolExecutor`?** Considera qué tipo de operación domina el procesamiento (I/O vs CPU) y las implicaciones del GIL de Python.

2. **¿Por qué el Script 2 convierte `UtcTime` a epoch milliseconds en lugar de mantener el formato datetime?** Piensa en las etapas posteriores del pipeline (correlación temporal Script 5).

### Ejercicio 2: Mapeo de EventIDs a Tácticas

Usando la tabla de EventIDs de Sysmon presentada en esta sección, mapea los siguientes escenarios de ataque APT al EventID que los detectaría:

| Escenario de ataque | EventID esperado |
|---------------------|-----------------|
| El atacante ejecuta `mimikatz.exe` para extraer credenciales | ? |
| Se establece un túnel DNS hacia un servidor C2 | ? |
| Se descarga un payload malicioso al disco | ? |
| Un proceso accede a la memoria de LSASS | ? |
| El atacante borra archivos para cubrir sus huellas | ? |

---

## Conclusiones

### Lo que hemos construido

En esta sección hemos recorrido el Script 2, que transforma los datos crudos de Sysmon en un CSV tabular listo para análisis:

| Entrada | Salida | Decisión clave |
|---------|--------|----------------|
| JSONL con XML embebido (2.1 GB) | CSV tabular (50 columnas, 363K filas) | Esquema unión de 21 EventIDs |

### Decisiones de diseño y sus consecuencias

Las decisiones tomadas en este script no son arbitrarias — cada una tiene consecuencias directas en etapas posteriores del pipeline:

1. **Epoch milliseconds en lugar de datetime strings**: Permite la correlación temporal con NetFlow en el Script 5 (Sesión 3). Ambos dominios comparten la misma escala numérica, haciendo que las operaciones de ventana temporal sean simples restas de enteros.

2. **Esquema unión (50 columnas con NaN)**: Mantiene todos los eventos en un solo DataFrame. La alternativa — un CSV por EventID — haría imposible el análisis cruzado entre tipos de eventos que el Script 8 (trazado de ciclo de vida) necesita.

3. **Normalización de Computer a minúsculas**: Evita que `ITM2-DC.intmaniac.local` y `ITM2-DC.INTMANIAC.LOCAL` se traten como hosts diferentes en el análisis de movimiento lateral.

4. **ProcessGuid sin llaves**: El formato limpio (`3fc4fefd-de08-67da-...`) facilita las operaciones de join y groupby que los Scripts 7 y 8 (etiquetado) realizan intensivamente.

### Conexión con lo que sigue

Tenemos un CSV de Sysmon con 50 columnas y ~363K filas. Pero antes de continuar con el pipeline, necesitamos verificar la calidad de este CSV: ¿la distribución de EventIDs es coherente? ¿Hay relaciones rotas entre procesos? ¿El dataset está listo para ML?

En la **siguiente sección** analizamos la calidad del CSV resultante — distribución de eventos, patrones temporales, relaciones entre procesos, y readiness para algoritmos de machine learning. Ese análisis nos revelará problemas concretos (como violaciones de ProcessGuid) que motivarán la sección de limpieza que viene después.
