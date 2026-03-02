# Exploración de Datos Crudos

**Duración**: 60 minutos

## Contexto: ¿Qué tenemos después de la extracción?

En la sección anterior utilizamos el script `1_elastic_index_downloader.py` para exportar la telemetría desde Elasticsearch. El resultado son archivos JSONL almacenados en el directorio de cada ejecución (*run*). Para la ejecución `run-01-apt-1`:

```
dataset/run-01-apt-1/
├── ds-logs-windows-sysmon_operational-default-run-01.jsonl   (2.1 GB, 363,657 registros)
└── ds-logs-network_traffic-flow-default-run-01.jsonl         (1.1 GB, 569,443 registros)
```

Tenemos dos archivos JSONL — uno por dominio de telemetría. Pero antes de escribir cualquier código de conversión o procesamiento, necesitamos responder una pregunta fundamental: **¿qué hay dentro de estos archivos?**

Este paso de exploración no es opcional. Sin entender la estructura interna de los datos, cualquier intento de conversión a CSV sería a ciegas: no sabríamos qué campos extraer, cómo manejar las estructuras anidadas, ni qué variaciones esperar entre registros.

## Paso 1: La unidad mínima de información

Cada línea de un archivo JSONL es un registro independiente — un documento JSON completo. El primer paso es leer **una sola línea** y examinarla:

```python
import json
import os

TARGET_PATH = "/ruta/al/dataset/run-01-apt-1/"
TARGET_FILE = "ds-logs-windows-sysmon_operational-default-run-01.jsonl"
TARGET_FILEPATH = os.path.join(TARGET_PATH, TARGET_FILE)

# Leer la primera línea del archivo
with open(TARGET_FILEPATH, 'r') as f:
    first_line = f.readline()

# Convertir de texto JSON a estructura Python
record = json.loads(first_line)
```

¿Qué tipo de dato es `record`?

```python
>>> type(record)
<class 'dict'>
```

Es un **diccionario**. Cada registro JSONL de Sysmon es un diccionario Python con pares clave-valor. Esta es nuestra unidad mínima de información: un solo evento de telemetría representado como un diccionario.

## Paso 2: Estructura de primer nivel

Ahora exploramos las claves y los tipos de datos de este diccionario:

```python
>>> for key, value in record.items():
...     print(f"{key:20s} -> {type(value).__name__}")
```

```
agent                -> dict
process              -> dict
winlog               -> dict
log                  -> dict
elastic_agent        -> dict
message              -> str
tags                 -> list
input                -> dict
@timestamp           -> str
file                 -> dict
ecs                  -> dict
related              -> dict
data_stream          -> dict
host                 -> dict
event                -> dict
user                 -> dict
```

**Observaciones importantes:**

1. Hay **16 campos de primer nivel**. La mayoría son diccionarios anidados (`dict`), con algunas excepciones: `message` es un string, `tags` es una lista, y `@timestamp` es un string.
2. Muchos de estos campos son **metadatos de Elasticsearch y Filebeat**, no datos de Sysmon propiamente dichos: `agent`, `elastic_agent`, `ecs`, `data_stream`, `input`, `tags`.
3. Los campos potencialmente relevantes para nuestra investigación son: `@timestamp`, `process`, `host`, `user`, `event`, y `winlog`.

Esta observación ya nos da una pista: no todo lo que viene en el JSONL es útil para nuestro dataset. Necesitaremos **seleccionar** qué información extraer.

## Paso 3: El descubrimiento clave — XML dentro de JSON

Al explorar el campo `event` encontramos algo inesperado:

```python
>>> record['event'].keys()
dict_keys(['agent_id_status', 'ingested', 'original', 'code', 'provider', 'created', 'kind', 'action', 'category', 'type', 'dataset'])
```

El subcampo `event['original']` contiene un string particularmente largo:

```python
>>> type(record['event']['original'])
<class 'str'>

>>> len(record['event']['original'])
2370

>>> print(record['event']['original'][:1000])
```

El resultado es un **bloque continuo de texto sin formato** — una sola línea larga sin saltos ni indentación:

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>
<EventID>7</EventID>
<Version>3</Version>
<Level>4</Level>
<Task>7</Task>
<Opcode>0</Opcode>
<Keywords>0x8000000000000000</Keywords>
<TimeCreated SystemTime='2025-03-19T06:09:05.866552600Z'/>
<EventRecordID>11346849</EventRecordID>
<Correlation/>
<Execution ProcessID='3556' ThreadID='5560'/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>WATERFALLS.boombox.local</Computer>
<Security UserID='S-1-5-18'/></System>
<EventData>
<Data Name='RuleName'>-</Data>
<Data Name='UtcTime'>2025-03-19 06:09:05.109</Data>
<Data Name='ProcessGuid'>{3fc4fefd-5f81-67da-7700-000000004900}</Data>
<Data Name='ProcessId'>5864</Data>
<Data Name='Image'>C:\Program Files\Microsoft\Exchange Server\V15\Bin\Microsoft.Exchange.ServiceHost.exe</Data>
<Data Name='ImageLoaded'>C:\Windows\System32\msvcrt.dll</Data>
<Data Name='FileVersion'>7.0.17763.475 (WinBuild.160101.0800)</Data>
<Data Name='Description'>Windows NT CRT DLL</Data>
<Data Name='Product'>Microsoft® Windows® Operating System</Data>
<Data Name='Company'>Microsoft Corporation</Data>
<Data Name='OriginalFileName'>msvcrt.dll</Data>
<Data Name='Hashes'>SHA256=39095FE07AC2E244E2180C58BEC2898A0986DDA2BD2ABBC4F739D11E67720F2E</Data>
<Data Name='Signed'>true</Data>
<Data Name='Signature'>Microsoft Windows</Data>
<Data Name='SignatureStatus'>Valid</Data>
<Data Name='User'>NT AUTHORITY\SYSTEM</Data>
</EventData>
<RenderingInfo Culture='en-US'>
<Message>
Image loaded:
RuleName: -
UtcTime: 2025-03-19 06:09:05.109
ProcessGuid: {3fc4fefd-5f81-67da-7700-000000004900}
ProcessId: 5864
Image: C:\Program Files\Microsoft\Exchange Server\V15\Bin\Microsoft.Exchange.ServiceHost.exe
ImageLoaded: C:\Windows\System32\msvcrt.dll
FileVersion: 7.0.17763.475 (WinBuild.160101.0800)
Description: Windows NT CRT DLL
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: msvcrt.dll
Hashes: SHA256=39095FE07AC2E244E2180C58BEC2898A0986DDA2BD2ABBC4F739D11E67720F2E
Signed: true
Signature: Microsoft Windows
SignatureStatus: Valid
User: NT AUTHORITY\SYSTEM</Message>
<Level>Information</Level>
<Task>Image loaded (rule: ImageLoad)</Task>
<Opcode>Info</Opcode>
<Channel></Channel>
<Provider></Provider>
<Keywords></Keywords>
</RenderingInfo>
</Event>
```

```{note}
En la salida real, el XML aparece como una sola línea continua sin espacios ni saltos de línea. Aquí lo mostramos con saltos para facilitar la lectura.
```

Este es el hallazgo fundamental de la exploración: **cada registro JSONL contiene el evento original de Sysmon como un string XML** incrustado dentro del campo `event.original`. Es XML del formato estándar de Windows Event Log.

### Estructura del XML de Sysmon

El XML tiene dos secciones principales:

```
<Event>
├── <System>            ← Metadatos del evento Windows
│   ├── <EventID>       ← Tipo de evento Sysmon (1, 3, 7, 10, 12, ...)
│   ├── <Computer>      ← Host que generó el evento
│   ├── <TimeCreated>   ← Timestamp de alta precisión
│   └── ...
│
└── <EventData>         ← Datos específicos del evento Sysmon
    ├── <Data Name="UtcTime">...</Data>
    ├── <Data Name="ProcessGuid">...</Data>
    ├── <Data Name="Image">...</Data>
    └── ...              ← Campos variables según el EventID
```

**Puntos clave:**

- `<System>` contiene metadatos comunes a todos los eventos: el `EventID` (que identifica el tipo de evento Sysmon), el nombre del equipo, y el timestamp.
- `<EventData>` contiene los campos específicos de cada tipo de evento. Un evento de creación de proceso (EventID 1) tendrá campos como `CommandLine` y `ParentImage`, mientras que un evento de conexión de red (EventID 3) tendrá `SourceIp` y `DestinationPort`.
- Los campos dentro de `<EventData>` **varían según el EventID**. Esto es crítico para el diseño del conversor CSV.

### ¿Por qué existe esta dualidad JSON + XML?

Elasticsearch almacena los documentos en formato JSON. Cuando Filebeat (el agente recolector) ingesta los eventos de Windows, realiza dos cosas:

1. **Parsea parcialmente** el evento, extrayendo algunos campos a la estructura JSON de primer nivel (`process`, `host`, `user`).
2. **Preserva el evento original** completo como un string XML en `event.original`.

Para nuestro propósito, el XML original en `event.original` es la fuente más fiable y completa de datos — contiene todos los campos de Sysmon sin transformaciones intermedias.

## Paso 4: Del descubrimiento al parser — prototipado paso a paso

Sabemos que los datos están en XML dentro de `event.original`. Ahora necesitamos **extraer información** de ese XML de forma programática. En lugar de escribir directamente una función completa, vamos a prototipar sobre el registro que ya tenemos en memoria.

### Intento 1: Parsing naive

Python incluye `xml.etree.ElementTree` para parsear XML. El primer intento es directo:

```python
import xml.etree.ElementTree as ET

xml_content = record['event']['original']
root = ET.fromstring(xml_content)
```

Esto funciona sin error — tenemos un árbol XML parseado. Ahora intentamos navegar a `<EventID>`:

```python
>>> root.find('EventID')
# None
>>> root.find('System')
# None
```

Ambas búsquedas devuelven `None`. El XML está parseado pero no encontramos los elementos. ¿Por qué?

### El problema: XML Namespaces

Si revisamos el inicio del XML:

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
```

El atributo `xmlns` declara un **namespace por defecto**. Esto significa que todos los elementos (`System`, `EventID`, `Computer`, etc.) pertenecen al namespace `http://schemas.microsoft.com/win/2004/08/events/event`. Para buscarlos con `ElementTree`, debemos declarar el namespace explícitamente:

```python
namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

# Ahora sí encontramos los elementos
>>> root.find('ns:System', namespaces)
<Element '{http://schemas.microsoft.com/win/2004/08/events/event}System' ...>
```

### Intento 2: Extraer los campos del `<System>`

Con el namespace resuelto, extraemos los metadatos del evento:

```python
system = root.find('ns:System', namespaces)

event_id_elem = system.find('ns:EventID', namespaces)
computer_elem = system.find('ns:Computer', namespaces)

print(f"EventID:  {event_id_elem.text}")
print(f"Computer: {computer_elem.text}")
```

```
EventID:  7
Computer: WATERFALLS.boombox.local
```

Funciona. Ya podemos identificar el **tipo de evento** y el **host** de cada registro.

### Intento 3: Extraer los campos de `<EventData>`

La sección `<EventData>` contiene múltiples elementos `<Data>` con un atributo `Name`. Necesitamos iterar sobre todos ellos:

```python
event_data = root.find('ns:EventData', namespaces)

fields = {}
for data in event_data.findall('ns:Data', namespaces):
    name = data.get('Name')
    value = data.text
    if name:
        fields[name] = value

# Veamos qué campos tiene este evento (EventID 7 = Image Loaded)
for name, value in fields.items():
    print(f"  {name:20s} = {str(value)[:60]}")
```

```
  RuleName             = -
  UtcTime              = 2025-03-19 06:09:05.109
  ProcessGuid          = {3fc4fefd-5f81-67da-7700-000000004900}
  ProcessId            = 5864
  Image                = C:\Program Files\Microsoft\Exchange Server\V15\Bin\Micro
  ImageLoaded          = C:\Windows\System32\msvcrt.dll
  FileVersion          = 7.0.17763.475 (WinBuild.160101.0800)
  Description          = Windows NT CRT DLL
  Product              = Microsoft® Windows® Operating System
  Company              = Microsoft Corporation
  OriginalFileName     = msvcrt.dll
  Hashes               = SHA256=39095FE07AC2E244E2180C58BEC2898A0986DDA2BD2ABC...
  Signed               = true
  Signature            = Microsoft Windows
  SignatureStatus      = Valid
  User                 = NT AUTHORITY\SYSTEM
```

Ahora tenemos un prototipo funcional: para cualquier registro, podemos extraer el EventID, el host, y todos los campos específicos del evento.

### De prototipo a función robusta

El prototipo funciona para nuestro registro de ejemplo, pero para aplicarlo a 363,657 registros necesitamos considerar:

1. **XML malformado**: Algunos registros pueden contener caracteres no imprimibles (bytes de control) que rompen el parser XML. Necesitamos una función de limpieza.
2. **Campos ausentes**: No todos los registros tendrán todos los elementos — el código debe manejar `None` sin fallar.
3. **Errores silenciosos**: Un registro corrupto no debe detener el análisis de los otros 363,656. Necesitamos `try/except`.

Estos son exactamente los problemas que resuelven las funciones `sanitize_xml` y `parse_sysmon_event` que veremos en el Paso 6.

## Paso 5: Explorar las variaciones — ¿Todos los registros son iguales?

Hemos examinado un solo registro. Pero un archivo JSONL con 363,657 líneas podría contener variaciones. Las preguntas clave son:

1. **¿Cuántos tipos de eventos (EventIDs) existen?** — Sysmon define más de 25 tipos diferentes.
2. **¿Qué campos tiene cada tipo?** — Cada EventID tiene su propio esquema de campos.
3. **¿Es consistente la estructura?** — ¿Todos los eventos del mismo tipo tienen exactamente los mismos campos?
4. **¿Cuántos hosts generan eventos?** — ¿Cuántas máquinas están representadas en los datos?

Para responder estas preguntas necesitamos analizar una muestra representativa del archivo. Con 363,657 registros, procesar el archivo completo es factible pero lento (el XML parsing es costoso). Una estrategia de **muestreo aleatorio** nos permite obtener resultados estadísticamente representativos en una fracción del tiempo:

```python
import random

# Contar total de registros
total_records = 0
with open(TARGET_FILEPATH, 'r') as f:
    for line in f:
        total_records += 1

print(f"Total records: {total_records:,}")
# Total records: 363,657

# Seleccionar 200,000 índices aleatorios (~55% del archivo)
SAMPLE_SIZE = 200_000
sample_indices = set(random.sample(range(total_records), min(SAMPLE_SIZE, total_records)))
```

**¿Por qué 200,000?** Es un equilibrio entre cobertura estadística y tiempo de procesamiento. Con un 55% del archivo muestreado aleatoriamente, cualquier patrón presente en al menos el 0.1% de los datos será capturado con alta probabilidad.

## Paso 6: Parsing del XML — De prototipo a función robusta

En el Paso 4 construimos un prototipo funcional para un solo registro. Para aplicarlo a los 200,000 registros muestreados, encapsulamos la lógica en funciones reutilizables y añadimos las capas de robustez que identificamos:

1. **`sanitize_xml`**: Limpia caracteres no imprimibles y repara XML malformado usando BeautifulSoup.
2. **`parse_sysmon_event`**: Encapsula la extracción de EventID, Computer y campos de `EventData`, con manejo de namespaces y excepciones.

```python
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

def sanitize_xml(xml_str):
    """Limpia caracteres inválidos y repara la estructura XML."""
    try:
        cleaned = ''.join(c for c in xml_str if 31 < ord(c) < 127 or c in '\t\n\r')
        return BeautifulSoup(cleaned, "xml").prettify()
    except:
        return xml_str

def parse_sysmon_event(xml_str):
    """Extrae EventID, Computer y campos de datos de un evento Sysmon XML."""
    try:
        clean_xml = sanitize_xml(xml_str)
        namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(clean_xml)

        # Sección System: metadatos del evento
        system = root.find('ns:System', namespaces)
        if not system:
            return None, None, {}

        event_id_elem = system.find('ns:EventID', namespaces)
        computer_elem = system.find('ns:Computer', namespaces)

        event_id = int(event_id_elem.text) if event_id_elem is not None else None
        computer = computer_elem.text if computer_elem is not None else None

        # Sección EventData: campos específicos del evento
        event_data = root.find('ns:EventData', namespaces)
        fields = {}
        if event_data:
            for data in event_data.findall('ns:Data', namespaces):
                name = data.get('Name')
                if name:
                    fields[name] = data.text if data.text else None

        return event_id, computer, fields
    except Exception:
        return None, None, {}
```

**Puntos clave:**

- `sanitize_xml` actúa como red de seguridad: limpia caracteres problemáticos y usa BeautifulSoup para reparar XML malformado. En nuestro dataset, menos del 0.01% de los registros necesitan esta limpieza.
- `parse_sysmon_event` extrae tres elementos: el **EventID** (tipo de evento), el **Computer** (host origen), y un **diccionario con todos los campos** de `EventData`.
- El manejo de excepciones con `try/except` garantiza que un registro corrupto no detenga el análisis completo.

## Paso 7: Resultados del análisis exploratorio

Al ejecutar el parsing sobre los 200,000 registros muestreados, obtenemos los siguientes resultados:

### Distribución de EventIDs

| EventID | Descripción | Conteo | Porcentaje |
|---------|------------|--------|------------|
| 10 | Process Access | 63,097 | 31.55% |
| 12 | Registry Event (Object create/delete) | 60,133 | 30.07% |
| 7 | Image/Library Loaded | 31,063 | 15.53% |
| 13 | Registry Event (Value Set) | 25,616 | 12.81% |
| 3 | Network Connection | 7,958 | 3.98% |
| 23 | File Delete | 5,564 | 2.78% |
| 11 | File Create | 3,699 | 1.85% |
| 1 | Process Creation | 534 | 0.27% |
| 5 | Process Terminated | 502 | 0.25% |
| ... | (10 EventIDs más) | ... | < 0.4% |

**Hallazgos:**

- Se encontraron **19 tipos de EventID** distintos en este run.
- La distribución está fuertemente concentrada: los **4 EventIDs más frecuentes** (10, 12, 7, 13) representan el **90%** de todos los registros.
- Los eventos de registro de Windows (EID 12 + 13) y los accesos a procesos (EID 10) dominan — esto es normal en un entorno Windows Server con Exchange.
- Los eventos de creación de procesos (EID 1), que son los más relevantes para la detección de ataques, representan solo el 0.27%. Esto ilustra por qué un dataset IDS necesita manejar un **fuerte desbalance de clases**.

### Distribución de hosts

| Host | Porcentaje |
|------|-----------|
| theblock.boombox.local | 40.98% |
| WATERFALLS.boombox.local | 39.92% |
| endofroad.boombox.local | 11.53% |
| diskjockey.boombox.local | 7.58% |

Se confirman **4 hosts** en el dominio `boombox.local`, con una distribución desigual: los servidores principales (`theblock`, `WATERFALLS`) generan ~80% de la telemetría.

### Ventana temporal

```
Timestamp más temprano: 2025-03-19T05:00:00.346Z
Timestamp más tardío:   2025-03-19T06:12:02.599Z
Duración total:         ~72 minutos
```

La ejecución completa de este run de ataque APT duró aproximadamente **72 minutos**.

### Tasa de éxito del parsing

- Registros parseados correctamente: **199,998 / 200,000** (99.999%)
- Errores de parsing: **2** registros con XML malformado

Esto confirma que la función `sanitize_xml` es necesaria (hay registros problemáticos), pero que la gran mayoría de los datos son estructuralmente correctos.

## Implicaciones para el diseño del conversor CSV

Esta exploración nos proporciona las bases para diseñar el conversor JSONL → CSV que veremos en la siguiente sección:

1. **La fuente de datos será `event.original`** — el XML incrustado, no los campos de primer nivel del JSON.
2. **Se necesita un esquema de campos por EventID** — cada tipo de evento tiene campos diferentes.
3. **El parsing XML debe ser robusto** — aunque el 99.99% de los registros son correctos, necesitamos manejar los casos de XML malformado.
4. **El procesamiento debe ser eficiente** — con cientos de miles de registros por archivo y 48 runs en total, la conversión debe poder ejecutarse en tiempo razonable (procesamiento multi-hilo, lectura en streaming).

## Actividad Práctica

### Ejercicio: Exploración del dominio NetFlow

Hasta ahora hemos explorado el archivo JSONL de **Sysmon** (eventos de host). El dataset también contiene un archivo JSONL de **NetFlow** (tráfico de red):

```
ds-logs-network_traffic-flow-default-run-01.jsonl  (569,443 registros)
```

Realiza la misma exploración inicial:

1. **Lee la primera línea** del archivo NetFlow y examina su estructura. ¿Es también un diccionario? ¿Cuántas claves de primer nivel tiene?

2. **¿Contiene XML incrustado?** Busca si existe un campo equivalente a `event.original`. Si no lo tiene, ¿dónde están los datos de tráfico de red?

3. **Compara las estructuras**: ¿Qué campos comparten ambos tipos de registro (Sysmon y NetFlow)? ¿Cuáles son exclusivos de cada dominio?

4. **Reflexiona**: Si NetFlow no usa XML incrustado, ¿cómo afecta esto al diseño del conversor CSV para el dominio de red?

### Resultado Esperado

Al finalizar esta sección, deberías comprender:

- Cómo realizar una exploración sistemática de datos crudos antes de cualquier procesamiento.
- La estructura de doble capa (JSON + XML) de los eventos Sysmon exportados desde Elasticsearch.
- La importancia de entender la distribución de EventIDs y la variabilidad de campos antes de diseñar un esquema de conversión.
- Las diferencias estructurales entre los dos dominios de telemetría (Sysmon vs NetFlow) y sus implicaciones para el procesamiento.
