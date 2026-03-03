# Análisis de Calidad del CSV Sysmon

**Duración**: 75 minutos

## Contexto: ¿Por qué analizar la calidad del CSV?

En la Sesión 1, completamos tres pasos fundamentales: exploramos los datos crudos JSONL (sección 3), verificamos la consistencia estructural (sección 4) y convertimos los datos a CSV (sección 5). Ahora tenemos un archivo CSV limpio con un esquema fijo por EventID.

Pero antes de usar estos datos para construir un sistema de detección de intrusiones, necesitamos responder: **¿los datos tienen la calidad suficiente para alimentar algoritmos de análisis causal?** Este análisis cubre distribución de eventos, patrones temporales, relaciones entre procesos, actividad de red/archivos, y una evaluación de "readiness" algorítmica.

```{tip}
El código de esta sección se puede ejecutar paso a paso en el notebook `2c-sysmon-csv-exploratory-analysis.ipynb`, que contiene el análisis completo con visualizaciones interactivas.
```

## Paso 1: Carga del CSV preprocesado

El CSV generado en la sección de preprocesamiento se carga con tipos de datos explícitos para garantizar un manejo correcto de valores nulos y eficiencia en memoria:

```python
import pandas as pd
import os

TARGET_PATH = "/path/to/dataset/run-01-apt-1/"
TARGET_FILE = "sysmon-run-01-corrected.csv"
TARGET_FILEPATH = os.path.join(TARGET_PATH, TARGET_FILE)

dtype_spec = {
    'ProcessId': 'Int64',          # Nullable integer (permite NaN)
    'SourcePort': 'Int64',
    'DestinationPort': 'Int64',
    'ProcessGuid': 'string',       # GUIDs como string
    'SourceProcessGUID': 'string',
    'Computer': 'category',        # Categorías para eficiencia
    'Protocol': 'category',
    'EventType': 'category'
}

df = pd.read_csv(TARGET_FILEPATH, low_memory=False, dtype=dtype_spec)
```

```
Registros cargados:   363,657
Columnas:             45
Uso de memoria:       525.58 MB
```

**¿Por qué especificar tipos de datos?** Pandas por defecto convierte columnas con valores faltantes a `float64`, lo que distorsiona PIDs y puertos (e.g., `648.0` en lugar de `648`). Usar `Int64` (nullable integer) preserva los valores enteros mientras permite `NA`. Las columnas categóricas (`Computer`, `Protocol`) reducen el uso de memoria significativamente.

**Verificación de tipos:**

| Tipo | Columnas | Ejemplo |
|------|----------|---------|
| `Int64` (nullable) | ProcessId, SourcePort, DestinationPort, SourceProcessId, ParentProcessId | `1212` |
| `string` | ProcessGuid, SourceProcessGUID, TargetProcessGUID, ParentProcessGuid | `44d66c27-4e6d-67da-1c00-000000007000` |
| `category` | Computer, Protocol, EventType | `WATERFALLS.boombox.local` |

Nota: los GUIDs en este dataset **no tienen llaves** (`{...}`), a diferencia del formato estándar Windows. Esto es importante para validaciones posteriores.

## Paso 2: Inspección básica del dataset

Una inspección inicial del DataFrame revela la estructura del CSV:

```
Filas:              363,657
Columnas:           45
EventIDs únicos:    20
Rango de EventID:   1 - 255
Hosts únicos:       4
```

**Las 45 columnas** representan la unión de todos los campos de los 19+ EventIDs, más una columna `timestamp` añadida durante el preprocesamiento. Las columnas son:

| # | Columna | # | Columna | # | Columna |
|---|---------|---|---------|---|---------|
| 1 | EventID | 16 | TargetImage | 31 | Protocol |
| 2 | Computer | 17 | SourceThreadId | 32 | SourceIsIpv6 |
| 3 | ProcessGuid | 18 | SourceUser | 33 | SourceIp |
| 4 | ProcessId | 19 | TargetUser | 34 | SourceHostname |
| 5 | Image | 20 | Hashes | 35 | SourcePort |
| 6 | TargetFilename | 21 | PipeName | 36 | SourcePortName |
| 7 | CreationUtcTime | 22 | CommandLine | 37 | DestinationIsIpv6 |
| 8 | User | 23 | CurrentDirectory | 38 | DestinationIp |
| 9 | EventType | 24 | ParentProcessGuid | 39 | DestinationHostname |
| 10 | TargetObject | 25 | ParentProcessId | 40 | DestinationPort |
| 11 | SourceProcessGUID | 26 | ParentImage | 41 | DestinationPortName |
| 12 | SourceProcessId | 27 | ParentCommandLine | 42 | PreviousCreationUtcTime |
| 13 | SourceImage | 28 | ImageLoaded | 43 | NewThreadId |
| 14 | TargetProcessGUID | 29 | OriginalFileName | 44 | Hash |
| 15 | TargetProcessId | 30 | Device | 45 | timestamp |

**Distribución de tipos de datos:**

| Tipo | Cantidad | Uso |
|------|----------|-----|
| `object` | 28 | Strings generales (paths, nombres, hashes) |
| `Int64` | 7 | PIDs, puertos (nullable) |
| `string[python]` | 4 | GUIDs |
| `int64` | 2 | EventID, campos enteros sin nulos |
| `category` | 3 | Computer, Protocol, EventType |
| `float64` | 1 | Columna numérica con nulos |

**Observaciones iniciales:**

- **20 EventIDs** en el CSV completo vs 19 en el muestreo de 200K del análisis de consistencia — el EventID adicional probablemente tiene muy pocos registros y no fue capturado en la muestra.
- **Rango de EventID hasta 255** es inesperado para Sysmon (que normalmente usa 1-25). Esto sugiere un EventID no estándar que merece investigación.
- Los nombres de host aparecen en **minúsculas** (`waterfalls.boombox.local`) a diferencia del JSONL crudo (`WATERFALLS.boombox.local`) — una normalización aplicada durante el preprocesamiento.

**Naturaleza dispersa del CSV unificado:**

Al inspeccionar las primeras filas (todas EventID 3 — Network Connection), se observa que las columnas de otros EventIDs están vacías (`NaN`/`<NA>`):

```
Row 0: EventID=3, Computer=diskjockey.boombox.local
  ✅ Protocol=udp, SourceIp=10.1.0.4, DestinationPort=53
  ❌ ImageLoaded=NaN, CommandLine=NaN, TargetObject=NaN, PipeName=NaN ...
```

Esto es consecuencia del diseño "una tabla para todos los EventIDs": cada fila solo tiene valores en las columnas relevantes para su tipo de evento. Las 45 columnas representan la unión de los campos de los 19+ EventIDs, pero cada registro individual solo usa entre 4 y 23 de ellas.

El análisis detallado de tipos y nulos por columna confirma y cuantifica la dispersión:

**Columnas sin valores nulos (presentes en todos los registros):**

| Columna | Tipo | Valores únicos |
|---------|------|----------------|
| EventID | int64 | 20 |
| Computer | category | 4 |
| timestamp | int64 | 92,018 |

**Columnas agrupadas por nivel de nulidad:**

| Grupo | Nulos (%) | Columnas | EventIDs relevantes |
|-------|-----------|----------|---------------------|
| Proceso general | 31.6% | ProcessGuid, ProcessId, Image, User | Todos excepto EID 4, 10 |
| Source/Target | 68.4% | SourceProcessGUID, TargetImage, SourceUser, etc. | EID 8, 10 |
| Red | 96.0% | Protocol, SourceIp, DestinationPort, etc. | Solo EID 3 |
| Creación proceso | 99.7% | CommandLine, ParentImage, ParentProcessId, etc. | Solo EID 1 |
| Muy raros | >99.9% | NewThreadId (6 valores), Hash (15), PreviousCreationUtcTime (212) | EID 8, 15, 2 |

**Observaciones de calidad:**

- **`NewThreadId`** es `float64` con solo 6 valores no nulos — corresponde a los 6 eventos de EID 8 (Create Remote Thread). El tipo debería ser `Int64` pero Pandas lo convierte a float por los nulos.
- **`EventType`** tiene 6 valores categóricos únicos: `SetValue`, `CreateKey`, `DeleteKey`, `CreatePipe`, `ConnectPipe`, y presumiblemente `DeleteValue`.
- **`timestamp`** es un epoch en milisegundos (ejemplo: `1742360400346`), diferente de `CreationUtcTime` que es un string datetime y solo tiene 7,009 valores no nulos.
- **16 usuarios únicos** (`User`) y solo **5 usuarios fuente** (`SourceUser`) — coherente con un entorno Windows corporativo.

## Paso 3: Distribución de eventos

*(Pendiente de resultados del notebook)*

## Paso 4: Análisis temporal

*(Pendiente de resultados del notebook)*

## Paso 5: Análisis de relaciones entre procesos

*(Pendiente de resultados del notebook)*

## Paso 6: Actividad de red

*(Pendiente de resultados del notebook)*

## Paso 7: Actividad del sistema de archivos

*(Pendiente de resultados del notebook)*

## Paso 8: Evaluación de calidad de datos

*(Pendiente de resultados del notebook)*

## Paso 9: Evaluación de readiness algorítmica

*(Pendiente de resultados del notebook)*

## Conclusiones

*(Pendiente de resultados del notebook)*
