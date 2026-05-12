# Análisis de Calidad del CSV Sysmon

**Duración**: 60 minutos

```{admonition} Script de trabajo
:class: note

**Notebook**: `8_sysmon_csv_exploratory_analysis.ipynb`

**Dataset**: Los archivos CSV de Sysmon están disponibles en [Google Drive](https://drive.google.com/drive/folders/1bLbcxM_mRAaeHIGTIy3PnAEOz0EcUMhA?usp=sharing).
```

## Contexto: ¿Por qué analizar la calidad del CSV?

En la sección anterior convertimos los datos Sysmon de formato JSONL a un CSV tabular de 45 columnas usando `7_sysmon_csv_creator.py`. Ahora tenemos un archivo CSV con un esquema unión que abarca los 20 tipos de EventID registrados en la captura.

Pero antes de usar estos datos para construir un sistema de detección de intrusiones, necesitamos responder: **¿los datos tienen la calidad suficiente para alimentar algoritmos de análisis causal?** Este análisis cubre distribución de eventos, patrones temporales, relaciones entre procesos, actividad de red/archivos, e integridad semántica de los identificadores de proceso (GUIDs).

```{note}
El código de esta sección se puede ejecutar paso a paso en el notebook `8_sysmon_csv_exploratory_analysis.ipynb`, que contiene el análisis completo con visualizaciones interactivas.
```

**Pipeline del análisis de calidad:**

```
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────────┐
  │ Paso 1:     │   │ Paso 2:      │   │ Paso 3:      │   │ Paso 4:        │
  │ Carga CSV   │──►│ Inspección   │──►│ Distribución │──►│ Análisis       │
  │ con dtypes  │   │ básica       │   │ de eventos   │   │ temporal       │
  └─────────────┘   └──────────────┘   └──────────────┘   └────────────────┘
                                                                  │
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐          │
  │ Paso 7:     │   │ Paso 6:      │   │ Paso 5:      │          │
  │ Sistema de  │◄──│ Actividad    │◄──│ Relaciones   │◄─────────┘
  │ archivos    │   │ de red       │   │ de procesos  │
  └─────────────┘   └──────────────┘   └──────────────┘
        │
        ▼
  ┌─────────────┐
  │ Paso 8:     │
  │ Evaluación  │
  │ de calidad  │
  └─────────────┘
```

**¿Por qué cada paso?**

1. **Carga con dtypes** — Garantizar tipos correctos desde el inicio evita errores silenciosos (ej. ProcessId como float por NaNs).
2. **Inspección básica** — Conocer dimensiones, columnas y proporción de nulos para saber con qué estamos trabajando.
3. **Distribución de eventos** — Identificar qué tipos de EventID dominan y cuáles son escasos, lo que afecta directamente al balance del dataset.
4. **Análisis temporal** — Verificar que la captura cubre el período esperado y detectar huecos o ráfagas anómalas de eventos.
5. **Relaciones de procesos** — Comprobar si los campos ProcessGuid y ParentProcessGuid permiten reconstruir árboles de procesos (esencial para trazar ataques).
6. **Actividad de red** — Evaluar si los eventos de conexión (EventID 3) contienen IPs, puertos y protocolos suficientes para correlacionar con NetFlow.
7. **Sistema de archivos** — Verificar la cobertura de eventos de creación/eliminación de archivos, que son indicadores clave de actividad maliciosa.
8. **Evaluación de calidad** — Cuantificar problemas concretos: duplicados, campos críticos vacíos, inconsistencias en GUIDs.

:::{admonition} Dependencia nueva: matplotlib y seaborn
:class: important

Esta sección usa `matplotlib` y `seaborn` para las visualizaciones. Si ejecutas el notebook localmente, instálalos antes de abrirlo:

**1. Activa tu entorno virtual:**
```bash
source .venv/bin/activate
```

**2. Instala las dependencias:**
```bash
pip install -r requirements.txt
```

**3. Abre el notebook desde el entorno activo** — si ya tenías el IDE abierto, ciérralo y vuélvelo a abrir con el entorno activado para que el kernel detecte los paquetes nuevos.
:::

## Paso 1: Carga del CSV preprocesado

El CSV generado en la sección anterior no se puede cargar con un `pd.read_csv()` sin configuración: su diseño de **esquema unión** — una sola tabla para los 20 tipos de EventID — produce columnas con mezcla de enteros y `NaN` que pandas malinterpreta por defecto. La carga correcta requiere dos parámetros explícitos:

```python
import pandas as pd
import os

TARGET_PATH = "../dataset/run-01-apt-1/"
TARGET_FILE = "02_sysmon-run-01.csv"
TARGET_FILEPATH = os.path.join(TARGET_PATH, TARGET_FILE)

dtype_spec = {
    'ProcessId': 'Int64',          # Nullable integer (permite NaN)
    'SourcePort': 'Int64',
    'DestinationPort': 'Int64',
    'SourceProcessId': 'Int64',
    'ParentProcessId': 'Int64',
    'SourceThreadId': 'Int64',
    'TargetProcessId': 'Int64',
    'ProcessGuid': 'string',       # GUIDs como string
    'SourceProcessGUID': 'string',
    'TargetProcessGUID': 'string',
    'ParentProcessGuid': 'string',
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

**¿Por qué `low_memory=False`?** Por defecto, pandas lee el CSV en bloques (*chunks*) para inferir el tipo de cada columna. En un CSV de esquema unión, una misma columna puede tener valores enteros en algunas filas y `NaN` en otras — dependiendo de qué bloque se lea primero, pandas puede inferir tipos distintos para la misma columna y generar errores silenciosos o warnings. `low_memory=False` fuerza la lectura de cada columna completa antes de inferir su tipo, garantizando consistencia. En un CSV de 363K filas con 45 columnas heterogéneas, esto es imprescindible.

**¿Por qué `dtype=dtype_spec`?** Incluso con `low_memory=False`, pandas aplica sus propias reglas de conversión por defecto: cualquier columna entera que contenga al menos un `NaN` se convierte automáticamente a `float64` — porque `NaN` es un concepto del tipo float en NumPy. En nuestro CSV esto afecta directamente a `ProcessId`, `SourcePort` y `DestinationPort`: son enteros, pero el esquema unión los deja vacíos en el 31–96% de las filas (los EventIDs que no usan esas columnas). Sin `dtype_spec`, un PID de `1212` aparecería en el DataFrame como `1212.0`. El tipo `Int64` (con mayúscula) es el entero *nullable* de pandas: acepta `NA` sin convertirse a float.

**Verificación de tipos:**

| Tipo | Columnas | Ejemplo |
|------|----------|---------|
| `Int64` (nullable) | ProcessId, SourcePort, DestinationPort, SourceProcessId, ParentProcessId, SourceThreadId, TargetProcessId | `1212` |
| `string` | ProcessGuid, SourceProcessGUID, TargetProcessGUID, ParentProcessGuid | `44d66c27-4e6d-67da-1c00-000000007000` |
| `category` | Computer, Protocol, EventType | `WATERFALLS.boombox.local` |

Nota: los GUIDs en este dataset **no tienen llaves** (`{...}`). El formato original de Windows los incluye (`{3fc4fefd-de08-67da-...}`), pero `7_sysmon_csv_creator.py` los elimina con `clean_guid()` durante el preprocesamiento. Esto es relevante para las validaciones del Paso 8, que verifican el formato sin llaves.

## Paso 2: Inspección básica del dataset

El notebook calcula `len(df)` y `len(df.columns)` para dimensiones, `nunique()` sobre `EventID` y `Computer` para cardinalidad, y para cada columna construye una tabla con `count()` (valores no nulos), `isnull().sum()` (nulos), porcentaje de nulidad, y `nunique()` (valores únicos). Esta última tabla es la fuente de los grupos de nulidad y las observaciones de calidad que siguen.

Una inspección inicial del DataFrame revela la estructura del CSV:

```
Filas:              363,657
Columnas:           45
EventIDs únicos:    20
Rango de EventID:   1 - 255
Hosts únicos:       4
```

**Las 45 columnas** representan la unión de todos los campos de los 19+ EventIDs. La columna 45, `timestamp`, es el resultado de convertir `UtcTime` (string datetime) a epoch en milisegundos durante el preprocesamiento (Script 2) — la columna original `UtcTime` se elimina y `timestamp` ocupa su lugar. Las columnas son:

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

Para una descripción detallada de qué significa cada columna y a qué EventID pertenece, consulta el [Apéndice: Event Data Collection](../appendices/event-data-collection.md#sysmon-events-and-fields-per-event).

**Distribución de tipos de datos:**

| Tipo | Cantidad | Uso |
|------|----------|-----|
| `object` | 28 | Strings generales (paths, nombres, hashes) |
| `Int64` | 7 | PIDs, puertos (nullable) |
| `string[python]` | 4 | GUIDs |
| `int64` | 2 | EventID, campos enteros sin nulos |
| `category` | 3 | Computer, Protocol, EventType |
| `float64` | 1 | Columna numérica con nulos |

El dataset es **multi-tipo por diseño** — consecuencia directa del esquema unión. Para la mayoría de operaciones (filtrado, agrupación, estadísticas) pandas lo maneja sin intervención. Pero hay dos casos donde los tipos importan y requieren atención explícita:

- **Operaciones entre columnas**: no se pueden mezclar tipos incompatibles (ej. `object` + `Int64`) sin conversión previa. En la práctica, el análisis de seguridad rara vez necesita esto.
- **Joins entre DataFrames**: las columnas clave deben tener exactamente el mismo tipo en ambos DataFrames. La distinción `int64` vs `Int64` (nullable) es una fuente real de errores silenciosos en pandas — un join entre una columna `int64` y una `Int64` puede fallar o producir resultados incorrectos sin ningún mensaje de error.

```{admonition} Pendiente — Sesión 3: correlación Sysmon–NetFlow
:class: warning

Cuando correlacionemos Sysmon con NetFlow por `timestamp` (y posiblemente por IP/puerto), hay que verificar que las columnas clave tengan tipos compatibles en ambos DataFrames antes de hacer el join. En particular: `timestamp` es `int64` en Sysmon — confirmar que NetFlow usa el mismo tipo y la misma escala (epoch en milisegundos).
```

**Observaciones iniciales:**

- **20 EventIDs únicos** en el dataset. El esquema de `7_sysmon_csv_creator.py` define 21 tipos en `FIELDS_PER_EVENTID`, pero los EventIDs 14 y 16 no tienen ningún registro en esta captura — son tipos de evento válidos de Sysmon que simplemente no se activaron durante el escenario APT de run-01.
- **Rango de EventID hasta 255** es inesperado para Sysmon (que normalmente usa 1-25). Con solo 1 registro, probablemente es un error interno de Sysmon al generar el evento. Se investiga en el Paso 8.

**Naturaleza dispersa del CSV unificado:**

Al inspeccionar las primeras filas (todas EventID 3 — Network Connection), se observa que las columnas de otros EventIDs están vacías (`NaN`/`<NA>`):

```
Row 0: EventID=3, Computer=diskjockey.boombox.local
  ✅ Protocol=udp, SourceIp=10.1.0.4, DestinationPort=53
  ❌ ImageLoaded=NaN, CommandLine=NaN, TargetObject=NaN, PipeName=NaN ...
```

Esto es consecuencia del diseño "una tabla para todos los EventIDs": cada fila solo tiene valores en las columnas relevantes para su tipo de evento. Las 45 columnas representan la unión de los campos de los 21 EventIDs definidos en el esquema, pero cada registro individual solo usa entre 4 y 23 de ellas.

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

La conclusión es directa: **los NaN no son datos faltantes — son la consecuencia estructural del esquema unión**. Cada columna tiene NaN exactamente en las filas cuyo EventID no usa esa columna. Esto no es un problema de calidad; es el comportamiento esperado del diseño explicado en la sección anterior.

**Observaciones de calidad:**

- **`NewThreadId`** es `float64` con solo 6 valores no nulos — corresponde a los 6 eventos de EID 8 (Create Remote Thread). El tipo debería ser `Int64` pero Pandas lo convierte a float por los nulos.
- **`EventType`** tiene 6 valores categóricos únicos: `SetValue`, `CreateKey`, `DeleteKey`, `CreatePipe`, `ConnectPipe`, y presumiblemente `DeleteValue`.
- **`timestamp`** es un epoch en milisegundos (ejemplo: `1742360400346`), diferente de `CreationUtcTime` que es un string datetime y solo tiene 7,009 valores no nulos.
- **16 usuarios únicos** (`User`) y solo **5 usuarios fuente** (`SourceUser`) — coherente con un entorno Windows corporativo.

## Paso 3: Distribución de eventos

El notebook aplica `value_counts()` sobre la columna `EventID` para obtener el recuento de registros por tipo de evento, y `value_counts(normalize=True)` para los porcentajes. Los resultados se ordenan por `EventID` con `sort_index()` para producir una tabla indexada numéricamente. A continuación se generan dos gráficas de barras — escala lineal y logarítmica — con los mismos datos para comparar la visibilidad de eventos frecuentes y raros.

La distribución de los 20 EventIDs en el dataset completo (363,657 registros):

| EventID | Descripción | Registros | % |
|---------|------------|-----------|---|
| 10 | Process Access | 114,736 | 31.55% |
| 12 | Registry Object create/delete | 109,413 | 30.09% |
| 7 | Image Load | 56,875 | 15.64% |
| 13 | Registry Value Set | 46,100 | 12.68% |
| 3 | Network Connection | 14,424 | 3.97% |
| 23 | File Delete | 10,126 | 2.78% |
| 11 | File Create | 6,782 | 1.86% |
| 18 | Pipe Connect | 1,280 | 0.35% |
| 9 | Raw Access Read | 1,170 | 0.32% |
| 1 | Process Create | 1,023 | 0.28% |
| 5 | Process Terminate | 900 | 0.25% |
| 17 | Pipe Create | 444 | 0.12% |
| 2 | File Creation Time | 212 | 0.06% |
| 24 | Clipboard Change | 77 | 0.02% |
| 6 | Driver Load | 67 | 0.02% |
| 15 | File Create Stream Hash | 15 | 0.00% |
| 8 | Create Remote Thread | 6 | 0.00% |
| 25 | Process Tampering | 5 | 0.00% |
| 4 | Sysmon State Change | 1 | 0.00% |
| **255** | **Unknown Event** | **1** | **0.00%** |

### Visualización de la distribución

La siguiente figura muestra la distribución completa de los 20 EventIDs en escala lineal (izquierda) y logarítmica (derecha):

![Distribución de EventIDs de Sysmon — escala lineal y logarítmica](/images/sysmon-eventid-distribution.png)

**Escala lineal:** Los EventIDs 10 y 12 dominan visualmente (~115K y ~110K), comprimiendo todos los demás en la base. La separación visual entre el rango estándar (1-25) y el EventID 255 confirma inmediatamente que 255 es un valor anómalo.

**Escala logarítmica:** Hace visibles los eventos raros que la escala lineal aplana. Tres órdenes de magnitud claramente distinguibles: frecuentes (>10K), moderados (100-10K), y raros (<100). Esta escala importa porque **EID 8 (Create Remote Thread) tiene solo 6 registros** — en escala lineal es invisible, pero es uno de los indicadores más directos de inyección de código. La diferencia de ~4 órdenes de magnitud entre EID 10 (114K) y EID 8 (6) es también el problema de desbalance de clases que cualquier modelo ML tendrá que resolver: con 6 ejemplos positivos, un clasificador no aprenderá a detectar inyección de código.

Para examinar el rango estándar sin la distorsión del EventID 255, se repite la visualización excluyendo EventIDs > 30:

![Distribución de EventIDs de Sysmon — rango estándar (1-25), escala lineal y logarítmica](/images/sysmon-eventid-distribution-zoomed.png)

Los huecos en el eje X (EventIDs 14, 16, 19-22) son EventIDs definidos en Sysmon que no generaron actividad en esta captura — comportamiento normal, no un problema de calidad.

**Observaciones:**

- Los **4 EventIDs dominantes** (10, 12, 7, 13) concentran el 89.95% del dataset — actividad de fondo típica de Windows (acceso entre procesos, operaciones de registro, carga de librerías).
- **EventID 255** (1 registro) es el evento de error interno de Sysmon — se genera cuando Sysmon encuentra un problema al procesar un evento. No es un tipo de telemetría de monitorización. Se investiga en el Paso 8.
- Los eventos de alto valor para detección de amenazas (**EID 1** Process Create, **EID 3** Network Connection, **EID 8** Create Remote Thread, **EID 11** File Create, **EID 23** File Delete) representan solo el 8.90% del total — el signal está enterrado en el noise.

## Paso 4: Análisis temporal

El notebook convierte `df['timestamp']` (int64, epoch ms) a `datetime64` con `pd.to_datetime(..., unit='ms', errors='coerce')`, almacenando el resultado en una nueva columna `UtcTime`. De ahí extrae `valid_times = df['UtcTime'].dropna()` para calcular el rango temporal (`min()` / `max()`), la duración como resta de dos `datetime64`, y las tasas de evento dividiendo `len(valid_times)` entre `duration.total_seconds()`. La visualización 2×2 se construye con cuatro operaciones de agrupación: `sort_values('UtcTime')` + `range(len(...))` para la timeline acumulativa; `.resample('1T').size()` para el histograma de eventos por minuto; `.dt.hour` + `value_counts().sort_index()` para el patrón horario; y `.resample('5T').size()` para la tasa en ventanas de 5 minutos.

El CSV no tiene una columna `UtcTime` directa, pero contiene `timestamp` — un epoch en milisegundos (int64) con cobertura del 100%. La conversión es directa:

```python
df['UtcTime'] = pd.to_datetime(df['timestamp'], unit='ms', errors='coerce')
```

```
Rango temporal:    2025-03-19 05:00:00 → 2025-03-19 06:12:02 UTC
Duración total:    1 hora, 12 minutos, 2 segundos
Timestamps válidos: 363,655 (100.0%)
Sin timestamp:      2 registros
```

**Tasas de eventos:**

| Métrica | Valor |
|---------|-------|
| Eventos por segundo | 84.14 |
| Eventos por minuto | 5,048.13 |
| Eventos por hora | 302,887.87 |

**Observaciones:**

- El dataset cubre una **ventana de ~72 minutos** de actividad, lo que indica una captura de un período específico de ejecución del escenario APT, no una monitorización continua.
- La tasa de ~84 eventos/segundo es considerable y refleja la intensidad de actividad en un entorno con 4 servidores Windows activos.
- Solo **2 registros** carecen de timestamp tras la conversión — los eventos EID 4 (Sysmon State Change) y EID 255 (error interno), ambos con el valor centinela `-9223372036855` que indica que Sysmon no registró timestamp para estos eventos. `errors='coerce'` los convierte en `NaT`.

**Patrones temporales (visualizaciones):**

```
Pico de eventos por minuto:     30,563
Promedio de eventos por minuto:  4,981.6
Hora más activa:  05:00 UTC (305,542 eventos)
Hora menos activa: 06:00 UTC (58,113 eventos)
```

El notebook genera 4 visualizaciones adaptadas a la ventana de 72 minutos, agrupadas en una única figura 2×2:

![Análisis temporal de eventos Sysmon — 4 visualizaciones](/images/sysmon-temporal-analysis.png)

1. **Timeline acumulativa** (arriba izquierda) — La línea acumulativa revela una curva en S con fases de intensidad variable. La pendiente más pronunciada se observa en los primeros ~10 minutos (05:00-05:10), donde se acumulan rápidamente más de 100K eventos. Después la pendiente se suaviza y vuelve a aumentar en torno a 05:35-05:45. Estos cambios de pendiente son la señal visual de ráfagas de actividad.
2. **Histograma de eventos/minuto** (arriba derecha) — La distribución está fuertemente sesgada a la derecha: la mayoría de los minutos registran menos de 2,000 eventos (las barras más altas, frecuencia ~11), pero la cola se extiende hasta ~30,000 eventos/minuto con una única ocurrencia. Esta forma confirma que la actividad no es uniforme — hay pocos minutos con ráfagas extremas que elevan drásticamente la media (~5,000) por encima de la moda (<2,000).
3. **Eventos por hora del día** (abajo izquierda) — Solo aparecen 2 barras (hora 5 con ~305K y hora 6 con ~58K), reflejando que la captura abarca únicamente 05:00-06:12 UTC. La proporción ~5:1 entre ambas barras es simplemente consecuencia de que la hora 5 tiene 60 minutos de datos y la hora 6 solo 12 — no indica un cambio real de intensidad.
4. **Tasa de eventos en ventanas de 5 minutos** (abajo derecha) — La visualización más reveladora. Se identifican **3 ráfagas diferenciadas**: un pico inicial de ~72K eventos (05:05-05:10), un segundo pico de ~45K (05:35-05:40), y un tercero de ~33K (06:00-06:05). Entre los picos, la tasa desciende a ~10K-20K. Este patrón multi-fase podría reflejar etapas distintas del escenario APT (ej: acceso inicial, movimiento lateral, exfiltración), aunque la correlación con fases específicas requiere el análisis de los Scripts 7-8 en sesiones posteriores.

```{dropdown} ¿Cuándo usar cada una de estas visualizaciones?
**Timeline acumulativa** — Útil cuando quieres detectar cambios en la *tasa de llegada* a lo largo del tiempo. Si la línea sube uniformemente, el proceso es estable; si tiene inflexiones o escalones, hay ráfagas, pausas o batches. Aplica a cualquier serie temporal: commits de git, transacciones bancarias, lecturas de sensores.

**Histograma de eventos/minuto** — Revela si el proceso es regular (distribución centrada) o bursty (cola larga a la derecha). Úsalo cuando la *variabilidad* de la tasa importa más que la tasa media: tráfico web, llamadas a una API, volumen de ventas por hora.

**Eventos por hora del día** — Detecta patrones diurnos o cíclicos. Especialmente útil cuando hay sospecha de periodicidad: actividad de fraude (se concentra en ciertos horarios), consumo energético, interacciones en redes sociales.

**Tasa en ventanas fijas** — La más útil para *detección de fases* en cualquier proceso acotado en el tiempo. Si el proceso tiene etapas distintas (experimento, campaña, incidente), aparecen como picos separados con valles entre ellos. La elección del tamaño de la ventana (aquí 5 minutos) es un parámetro clave: ventanas muy pequeñas producen ruido, muy grandes ocultan las fases.
```

**Puntos clave:**
- La ventana de **72 minutos** confirma que el dataset captura un período específico de ejecución del escenario APT, no una monitorización continua — cada evento en esta ventana es potencialmente relevante.
- La tasa de 84 eventos/segundo con picos de 30,563/minuto indica **ráfagas de actividad** que podrían corresponder a fases específicas del ataque (ejecución, movimiento lateral, exfiltración).
- Solo 2 registros sin timestamp (0.0005%) representan una tasa de integridad temporal excepcional para un dataset de esta escala.
- El epoch en milisegundos (`timestamp`) proporciona la **misma resolución temporal** que el dominio NetFlow, habilitando la correlación cruzada en la Sesión 3.

## Paso 5: Análisis de relaciones entre procesos

Los eventos Sysmon identifican procesos mediante dos mecanismos complementarios: **GUIDs** (identificadores globales únicos por instancia de proceso) y **PIDs** (identificadores numéricos reutilizables por el sistema operativo). Su relación es asimétrica: Windows asigna PIDs secuencialmente en un rango finito (~65K valores), y una vez que un proceso termina su PID queda libre para ser reasignado a un nuevo proceso. Sysmon garantiza que el `ProcessGuid` es único por instancia de proceso — incluso si el PID es reasignado a un nuevo proceso más tarde, cada instancia recibe un GUID diferente. Consecuencia directa: un mismo PID puede aparecer asociado a varios GUIDs distintos por dos razones. La primera es **temporal**: un proceso termina, su PID queda libre y es reasignado a un nuevo proceso en la misma máquina. La segunda, y más evidente en un dataset multi-host, es **cross-host**: el mismo valor de PID existe simultáneamente en varias máquinas — el caso más claro es el PID 4 (`System`, el kernel de Windows), que por diseño siempre tiene ese PID en cualquier Windows y por tanto aparece con un GUID distinto en cada host. En este dataset, PID 4 tiene 8 GUIDs: 2 por cada uno de los 4 hosts (el segundo GUID indica que el sistema se reinició durante la captura). Un GUID, en cambio, siempre identifica exactamente una instancia de proceso en una máquina concreta. Analizar ambos revela cuál es fiable para rastreo causal.

Los 4 pares GUID/PID que aparecen en la tabla responden a dos tipos de relación entre procesos que Sysmon modela con nombres de columna distintos:

- **`ProcessGuid` / `ParentProcessGuid`** — relación **vertical (genealógica)**: un proceso padre *spawneó* al proceso hijo. `ProcessGuid` identifica al proceso que generó el evento; `ParentProcessGuid` al que lo creó. Presentes en la mayoría de EventIDs, con `ParentProcessGuid` exclusivo de EID 1 (Process Create).
- **`SourceProcessGUID` / `TargetProcessGUID`** — relación **lateral (interacción en tiempo de ejecución)**: dos procesos independientes donde uno actúa sobre el otro. `SourceProcessGUID` es el proceso que inicia la acción; `TargetProcessGUID` el que la recibe. Presentes en EID 8 (Create Remote Thread) y EID 10 (Process Access) — ninguno creó al otro, simplemente interactúan. En seguridad, estos dos EventIDs son indicadores directos de técnicas de inyección de código.

El notebook evalúa los 4 pares: para cada uno filtra las filas donde ambas columnas son no-nulas, cuenta GUIDs únicos y PIDs únicos con `nunique()`, y cuenta combinaciones únicas GUID-PID con `groupby([guid_col, pid_col]).size().shape[0]`. El **ratio de reuso** = combinaciones / PIDs únicos: si es > 1, hay PIDs que aparecen con múltiples GUIDs distintos — reutilización confirmada.

**Pares GUID/PID en el dataset:**

| Par de columnas | Pares no nulos | GUIDs reales únicos | PIDs únicos | Combinaciones GUID-PID únicas | PID reuse |
|-----------------|----------------|---------------------|-------------|-------------------------------|-----------|
| ProcessGuid / ProcessId | 248,846 | 1,632 | 1,240 | 1,632 | 1.32 ⚠️ |
| ParentProcessGuid / ParentProcessId | 1,023 | 234 | 223 | 234 | 1.05 |
| SourceProcessGUID / SourceProcessId | 114,742 | 493 | 447 | 493 | 1.10 ⚠️ |
| TargetProcessGUID / TargetProcessId | 114,742 | 1,420 | 1,143 | 1,420 | 1.24 ⚠️ |

**Interpretación:**

- **PID reuse confirmado** en 3 de 4 pares (ratio ≥ 1.10). El par ProcessGuid/ProcessId muestra el ratio más alto (1.32): cada PID está asociado en promedio a 1.32 instancias de proceso distintas, lo que refleja tanto reasignación temporal dentro de una misma máquina como la coexistencia del mismo PID en los 4 hosts del dataset.
- **Ningún GUID real mapea a más de un PID**: en todos los pares, el número de combinaciones GUID-PID es igual al número de GUIDs reales únicos. La asimetría del ratio opera exclusivamente en dirección inversa — múltiples GUIDs comparten un mismo PID (reutilización normal del sistema operativo), nunca un GUID con PIDs inconsistentes.
- **GUIDs son el identificador confiable**: los 1,632 GUIDs reales identifican cada uno exactamente una instancia de proceso — la excepción es el GUID centinela `00000000-0000-0000-0000-000000000000`, examinado en detalle en el **Paso 8e**.
- **ParentProcess** solo tiene 1,023 pares no nulos — exclusivamente de EventID 1 (Process Create), el único tipo de evento que registra información del proceso padre.
- **Source/Target** tienen 114,742 pares no nulos — de EventIDs 8 (Create Remote Thread) y 10 (Process Access), que modelan interacciones entre dos procesos.

**Implicación para algoritmos causales**: Cualquier algoritmo de análisis causal **debe usar GUIDs, no PIDs**, para rastrear procesos. Usar PIDs produciría falsos positivos por reutilización.

### 5b. Análisis de creación de procesos (EventID 1)

EventID 1 (Process Create) es el evento clave para reconstruir el árbol de procesos. Cada registro EID 1 captura la instancia de proceso recién creada (child) en los campos `ProcessGuid`/`ProcessId`, y registra simultáneamente los identificadores del proceso que la creó (parent) en `ParentProcessGuid`/`ParentProcessId`. Esta estructura — cada evento EID 1 lleva un puntero explícito al proceso que lo creó — permite reconstruir el árbol de procesos completo. Partiendo de cualquier proceso, se pueden trazar hacia atrás todos sus ancestros (siguiendo `ParentProcessGuid` en cadena) y hacia adelante todos los eventos que generó durante su vida: conexiones de red (EID 3), cargas de imagen (EID 7), accesos a registro (EID 12/13), accesos a otros procesos (EID 10), hasta su terminación (EID 5) — y recursivamente para cada proceso hijo (EID 1) que spawneó.

**Operaciones del código**: el código filtra `EventID == 1` y cuenta los registros donde ambos `ProcessGuid` y `ParentProcessGuid` son no nulos (pares padre-hijo válidos), y los que tienen `ParentProcessGuid` nulo (huérfanos). Para las estadísticas de padres, aplica `value_counts()` sobre `ParentProcessGuid` para contar cuántos hijos tiene cada GUID padre, obteniendo media y máximo. Para identificar el proceso padre por nombre, busca el GUID padre en la columna `ProcessGuid` del mismo subconjunto EID 1 — si no hay coincidencia, el padre se inició antes de la ventana de captura y no tiene evento EID 1 propio en el dataset.

```
Eventos de creación de procesos:    1,023
Con relación padre-hijo válida:     1,023 (100%)  ⚠️ ver nota
Procesos huérfanos (sin padre):     0
```

> **Nota**: la verificación usa `.notna()` sobre `ParentProcessGuid`, que no distingue el GUID centinela `00000000-...` de un GUID real — ambos son strings no nulos. De los 1,023 registros que pasan el filtro, **500 tienen el GUID centinela como padre** (padre no identificable por Sysmon). Solo **523 tienen un `ParentProcessGuid` real y trazable**. Este detalle se examina en el **Paso 8e**.

**Estadísticas de procesos padre:**

| Métrica | Valor |
|---------|-------|
| Padres únicos con hijos | 235 |
| Promedio de hijos por padre | 4.4 |
| Máximo hijos de un solo padre | 500 |
| Padres con >10 hijos | 9 |

```{warning}
El máximo de 500 hijos generados por un único padre es anómalo. ¿Puede un proceso legítimo spawnear 500 procesos hijos en una ventana de 72 minutos? ¿O es un artefacto en los datos? Este valor merece investigación propia — analizada en el **Paso 8e**.
```

**Top 5 procesos padre más prolíficos:**

| Hijos | Proceso padre |
|-------|---------------|
| 500 | *No encontrado en el dataset* |
| 44 | *No encontrado en el dataset* |
| 31 | `C:\Users\Public\SystemFailureReporter.exe` |
| 19 | *No encontrado en el dataset* |
| 19 | `C:\Program Files\Google\Chrome\Application\chrome.exe` |

**Hallazgos de seguridad:**

- **"Parent not found in dataset"** puede significar dos cosas distintas. Para los padres con 44 y 19 hijos: el proceso padre fue creado *antes* del inicio de la ventana de captura (05:00 UTC) — su GUID existe en los registros EID 1 de sus hijos, pero no hay un evento EID 1 propio en el dataset (GUID real, solo ausente del CSV). Para el padre con 500 hijos: es el GUID centinela `00000000-...`, cuya causa se investiga en el **Paso 8e**.
- **`SystemFailureReporter.exe`** en `C:\Users\Public\` es altamente sospechoso: un ejecutable con nombre engañoso ubicado en una carpeta pública (accesible por cualquier usuario). Con 31 procesos hijos, es consistente con un implante de la simulación APT.
- **Chrome con 19 hijos** es comportamiento normal — cada pestaña y extensión genera procesos hijos.

### 5c. Análisis de líneas de comando (EventID 1)

El campo `CommandLine` registra el comando completo con el que se invocó el proceso, incluyendo ejecutable y argumentos. Solo EventID 1 popula este campo; el resto de los EventIDs lo dejan en blanco. Esto lo convierte en una fuente de señales de alta fidelidad para detección de técnicas ofensivas: comandos codificados en base64, bypass de políticas de ejecución, o descarga remota de payloads.

**Operaciones del código**: el código filtra primero por `EventID == 1` y dentro de ese subconjunto verifica qué registros tienen `CommandLine` no nulo, reportando la cobertura dentro de EID 1. Extrae el "comando base" tomando la primera palabra de la cadena y eliminando la ruta del directorio con una expresión regular (`str.replace(r'.*\\', '')`) para quedarse solo con el nombre del ejecutable. Aplica `value_counts()` sobre ese campo derivado para obtener el top-15. Para la longitud, calcula media, mediana y máximo de `CommandLine.str.len()`, y cuenta las líneas que superan los 500 y 1,000 caracteres. Finalmente busca patrones sospechosos con `str.contains()` sobre expresiones regulares predefinidas.

Solo 1,023 eventos (0.3%) tienen línea de comando — exclusivamente EventID 1 (Process Create).

**Comandos más frecuentes (top 5):**

| Comando base | Ejecuciones | % |
|-------------|-------------|---|
| program* | 239 | 23.4% |
| svchost.exe | 94 | 9.2% |
| conhost.exe | 70 | 6.8% |
| dllhost.exe | 60 | 5.9% |
| wmiprvse.exe | 50 | 4.9% |

*\* "program" es un artefacto de parsing: proviene de rutas como `"C:\Program Files\...\app.exe"` donde la extracción del comando base falla al dividir por espacios antes de eliminar la ruta.*

```{dropdown} ¿Qué son svchost.exe, conhost.exe, dllhost.exe y wmiprvse.exe?
**`svchost.exe`** — Service Host. El proceso contenedor de servicios de Windows. El sistema operativo no ejecuta sus servicios directamente — los agrupa dentro de instancias de `svchost.exe`. En cualquier Windows hay docenas de instancias corriendo simultáneamente, cada una alojando uno o más servicios (DNS, Windows Update, RPC, etc.). Es el ejecutable más lanzado del sistema.

**`conhost.exe`** — Console Host. Cada vez que se abre una ventana de consola (`cmd.exe`, PowerShell, etc.) Windows crea un `conhost.exe` asociado que maneja la ventana de la terminal. En un escenario APT con mucha actividad de línea de comandos, es esperado ver muchas instancias.

**`dllhost.exe`** — DLL Host / COM Surrogate. Ejecuta componentes COM (Component Object Model) en un proceso separado, aislado del proceso que los invoca. Aparece frecuentemente al acceder a carpetas con miniaturas, al ejecutar tareas programadas COM, y en muchas operaciones internas de Windows.

**`wmiprvse.exe`** — WMI Provider Service. Ejecuta los proveedores WMI (Windows Management Instrumentation). Cualquier consulta WMI — del sistema, de software de monitorización, o de un atacante usando WMI para movimiento lateral — genera una instancia de este proceso.

**Relevancia en un escenario APT**: aunque son todos procesos legítimos, son los favoritos para técnicas de evasión. Un atacante puede inyectar código en `svchost.exe` o `dllhost.exe` precisamente porque son ubicuos — se mezclan con el ruido de fondo. En el Paso 8e veremos que muchos de estos procesos aparecen con `ParentProcessGuid` centinela, lo que confirma que se lanzan en las fases tempranas del sistema donde la visibilidad de Sysmon es limitada.
```

**Longitud de líneas de comando:**

```
Promedio:   170.3 caracteres
Mediana:     59.0 caracteres
Máximo:    5,584 caracteres
>500 chars:   46 comandos
>1000 chars:  14 comandos
```

La diferencia entre media (170) y mediana (59) indica una distribución sesgada: la mayoría son comandos cortos, pero algunos tienen miles de caracteres — potencialmente comandos codificados u ofuscados.

**Patrones sospechosos detectados:**

| Patrón | Ocurrencias | Relevancia |
|--------|-------------|------------|
| Script execution (.ps1, .bat, .cmd, .vbs) | 15 | Ejecución de scripts — común en técnicas de ataque |
| Download commands (wget, curl, Invoke-WebRequest) | 4 | Descarga de payloads — indicador de C2 |
| PowerShell ExecutionPolicy Bypass | 1 | Evasión de restricciones — técnica clásica de post-explotación |

Estos patrones, junto con `SystemFailureReporter.exe` del análisis anterior y la presencia de `cmd.exe` (41 ejecuciones) y `netsh` (12 ejecuciones), son consistentes con las fases de ejecución y movimiento lateral de una simulación APT.

### 5d. Análisis de Image (EventID 1)

El campo `Image` contiene la ruta completa del ejecutable creado. Mientras `CommandLine` responde "¿cómo fue invocado el proceso?", `Image` responde "¿qué proceso fue creado y desde dónde?". La ubicación del ejecutable en el sistema de archivos es en sí misma una señal de seguridad: los binarios del sistema operativo residen en rutas predecibles (`System32`, `SysWOW64`), y cualquier ejecutable fuera de esas rutas merece escrutinio.

**Operaciones del código**: el código filtra por `EventID == 1` y verifica cobertura de `Image` dentro de EID 1, separando nulos y `<unknown process>`. Extrae el nombre del ejecutable y el directorio de origen con expresiones regulares sobre la ruta en minúsculas. Aplica `value_counts()` para obtener el top-10 de ejecutables y de directorios. Finalmente evalúa cada ruta contra un conjunto de patrones de directorios sospechosos (`C:\Users\Public`, `AppData`, carpetas Temp, `ProgramData`).

```
EID 1 events:          1,023
Null Image:            0
<unknown process>:     0
Valid Image:           1,023 (100.0%)
```

**Top 10 ejecutables creados:**

| Ejecutable | Instancias |
|-----------|-----------|
| svchost.exe | 94 |
| conhost.exe | 70 |
| dllhost.exe | 60 |
| wmiprvse.exe | 50 |
| cmd.exe | 50 |
| taskhostw.exe | 40 |
| firefox.exe | 37 |
| backgroundtaskhost.exe | 35 |
| runtimebroker.exe | 30 |
| updater.exe | 26 |

Los primeros cuatro son infraestructura del sistema operativo (ver Paso 5c). `taskhostw.exe`, `backgroundtaskhost.exe` y `runtimebroker.exe` son parte de la infraestructura de tareas programadas y apps modernas de Windows — presencia esperada. `updater.exe` proviene de los procesos de actualización de Google Chrome y Microsoft Edge, confirmados por los directorios de origen.

**Top 10 directorios de origen:**

| Directorio | Instancias |
|-----------|-----------|
| `C:\Windows\System32` | 639 |
| `C:\Windows\System32\wbem` | 59 |
| `C:\Program Files\Mozilla Firefox` | 41 |
| `C:\Program Files (x86)\Google\GoogleUpdater\135.0.7023.0` | 25 |
| `C:\Program Files (x86)\Microsoft\EdgeUpdate` | 20 |
| `C:\Program Files\Google\Chrome\Application` | 20 |
| `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\134.0.3124.72` | 16 |
| `C:\Program Files\Microsoft OneDrive\25.031.0217.0003` | 15 |
| `C:\Windows\SysWOW64` | 15 |
| `C:\Windows` | 14 |

El 62% (639/1,023) de los procesos creados provienen de `System32` — distribución normal para un sistema Windows activo.

**Ejecutables en rutas sospechosas:**

| Ruta | Instancias | Ejecutable |
|------|-----------|-----------|
| `C:\Users\Public\` | 1 | `SystemFailureReporter.exe` |
| `C:\Users\Public\Downloads\` | 1 | `plink.exe` |
| `C:\Users\gosta\AppData\Local\Microsoft\EdgeUpdate\` | 1 | `MicrosoftEdgeUpdate.exe` |
| `C:\Users\gosta\AppData\Local\SystemFailureReporter\` | 1 | `b.exe` |
| `C:\Windows\Temp\` | 1 | `m64.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\...\` | 3 | `MpCmdRun.exe` |
| `C:\ProgramData\VMware\` | 1 | `VMware.exe` |

**Hallazgos de seguridad:**

- **`plink.exe`** en `C:\Users\Public\Downloads\` — PLink es el cliente SSH de línea de comandos de la suite PuTTY. Herramienta legítima de administración, pero clásicamente usada en ataques para establecer túneles SSH como canal C2 encubierto. Su presencia en una carpeta de acceso público es un indicador fuerte de tunneling o movimiento lateral.

- **`b.exe`** en `C:\Users\gosta\AppData\Local\SystemFailureReporter\` — el mismo nombre de carpeta que el implante `SystemFailureReporter.exe` de `C:\Users\Public\`, pero un binario distinto (`b.exe`). Sugiere una arquitectura de dos componentes: el ejecutable principal en Public (accesible a todos los usuarios) y un componente secundario en el perfil del usuario comprometido.

- **`m64.exe`** en `C:\Windows\Temp\` — ejecutable de nombre ultracorto en una carpeta temporal. El patrón nombre-corto + ruta-Temp es característico de herramientas de ataque que se copian a sí mismas en Temp para ejecución efímera. `m64` podría ser una variante de Mimikatz u otra herramienta de post-explotación.

- **`MpCmdRun.exe`** — herramienta CLI legítima de Windows Defender. Sin embargo, es también un LOLBin (Living-off-the-Land Binary) conocido: atacantes lo usan para descargar archivos y evadir detección aprovechando que es un binario firmado por Microsoft.

- **`VMware.exe`** en `C:\ProgramData\VMware\` — agente del entorno de laboratorio virtualizado. Presencia esperada, no sospechosa.

## Paso 6: Actividad de red

El análisis de EventID 3 (Network Connection) examina 14,424 conexiones de red capturadas durante la ventana de 72 minutos.

**Operaciones del código**: el código filtra `EventID == 3` y aplica `value_counts()` sobre `Protocol` para la distribución TCP/UDP. Para los puertos de destino, cuenta con `value_counts()` sobre `DestinationPort` y aplica un diccionario de mapeo de puertos a nombres de servicio. Para la clasificación de IPs, evalúa `DestinationIP` contra rangos de red privados (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, `::1`, `fe80::`) para separar tráfico interno de externo.

**Distribución de protocolos:**

| Protocolo | Conexiones | % |
|-----------|-----------|---|
| TCP | 8,813 | 61.1% |
| UDP | 5,611 | 38.9% |

**Top puertos de destino:**

| Puerto | Servicio | Conexiones | % |
|--------|----------|-----------|---|
| 53 | DNS | 2,265 | 15.7% |
| 443 | HTTPS | 2,121 | 14.7% |
| 444 | — | 1,378 | 9.6% |
| 389 | LDAP | 1,099 | 7.6% |
| 88 | Kerberos | 819 | 5.7% |
| 6001 | — | 748 | 5.2% |
| 81 | — | 592 | 4.1% |
| 80 | HTTP | 410 | 2.8% |
| 445 | SMB | 139 | 1.0% |

**Clasificación de IPs de destino:**

```
IPs de destino únicas:    189
IPs privadas/locales:     8,004 (55.5%)
IPs públicas:             6,420 (44.5%)
```

14,424 conexiones repartidas entre solo 189 IPs destino — un promedio de 76 conexiones por IP. Esta concentración indica comunicación repetida con un conjunto reducido de servidores, no exploración aleatoria de la red.

El 55.5% de tráfico interno refleja comunicación normal entre los 4 hosts del laboratorio y sus servicios de dominio (Kerberos, LDAP, DNS). El 44.5% externo tiene dos explicaciones complementarias: por un lado, los actualizadores automáticos de Chrome, Firefox, Edge y OneDrive (identificados en el Paso 5d generando 96 procesos) abren conexiones hacia CDNs y servidores de actualización públicos; por otro, la presencia de `plink.exe` en `C:\Users\Public\Downloads\` y los puertos no estándar 444 y 6001 apuntan a tráfico C2 encubierto entre esa actividad legítima.

**Top IPs de destino:**

| IP | Conexiones | % | Contexto |
|----|-----------|---|----------|
| 10.1.0.4 | 3,572 | 24.8% | Red interna (diskjockey) |
| fe80::fddc:bbf3:656b:f0fd | 2,590 | 18.0% | IPv6 link-local |
| 10.1.0.6 | 2,096 | 14.5% | Red interna (WATERFALLS) |
| ::1 | 1,775 | 12.3% | IPv6 localhost |
| 10.1.0.5 | 1,122 | 7.8% | Red interna |
| 127.0.0.1 | 1,047 | 7.3% | Localhost |
| **8.8.8.8** | **924** | **6.4%** | **DNS público de Google** |

**Hallazgos de seguridad:**

- **Puerto 444** (1,378 conexiones) no es un servicio estándar. En el contexto de esta simulación APT, podría ser un canal de comando y control (C2) — los atacantes frecuentemente usan puertos similares a servicios legítimos (443+1).
- **Puerto 6001** (748 conexiones) y **puerto 81** (592 conexiones) son igualmente no estándar y merecen investigación como posibles canales C2.
- **8.8.8.8** como destino frecuente (924 conexiones) podría ser DNS legítimo o exfiltración vía DNS — una técnica APT conocida.
- **Puertos 88 (Kerberos)** y **389 (LDAP)** son esperables en un dominio Windows Active Directory.
- El 44.5% de tráfico hacia IPs públicas es significativo para un entorno de laboratorio. Parte es legítima (updaters de Chrome, Edge, OneDrive), pero correlaciona directamente con `plink.exe` (Paso 5d) — un cliente SSH usado para tunneling — y con los puertos no estándar 444 y 6001, reforzando la hipótesis de canal C2 encubierto.

## Paso 7: Actividad del sistema de archivos

El análisis combina EventID 11 (File Create) y EventID 23 (File Delete).

**Operaciones del código**: el código filtra dos subsets: `EventID == 11` y `EventID == 23`. Para las extensiones, aplica `str.extract(r'\.([^.\\]+)$')` sobre `TargetFilename` para capturar el sufijo final, convierte a minúsculas y cuenta con `value_counts().head(15)`. Para la ubicación, clasifica cada ruta con `str.contains()` usando expresiones regulares para cuatro categorías (temp, system32/windows, users/home, appdata) — las categorías se solapan (AppData está dentro de Users), por lo que los porcentajes no suman 100%. Para los patrones de interés, aplica regexes sobre extensiones ejecutables, nombres con punto inicial (archivos ocultos estilo Unix) y longitud de ruta completa >100 caracteres.

```
Eventos de creación de archivos (EID 11):   6,782
Eventos de eliminación de archivos (EID 23): 10,126
```

La ratio eliminación/creación de 1.49 indica que se eliminan más archivos de los que se crean — comportamiento normal de limpieza del sistema, pero también consistente con técnicas anti-forenses de APTs.

**Extensiones más frecuentes en archivos creados:**

| Extensión | Archivos | % | Contexto |
|-----------|----------|---|----------|
| .tmp | 1,161 | 17.1% | Archivos temporales del sistema |
| .svg | 348 | 5.1% | Gráficos vectoriales (Chrome/Exchange) |
| .log | 282 | 4.2% | Logs del sistema |
| .dat | 275 | 4.1% | Datos binarios |
| .dll | 264 | 3.9% | Librerías — puede indicar DLL sideloading |
| .pf | 238 | 3.5% | Prefetch de Windows |
| .png | 224 | 3.3% | Imágenes (Chrome/navegación) |

**Ubicación de archivos creados:**

| Ubicación | Archivos | % |
|-----------|----------|---|
| AppData | 2,940 | 43.4% |
| Directorios de usuario | 2,882 | 42.5% |
| Directorios del sistema | 1,310 | 19.3% |
| Directorios temporales | 507 | 7.5% |

Los porcentajes no suman 100% porque las categorías se solapan: AppData (`C:\Users\*\AppData\`) está contenido dentro de "directorios de usuario" (`C:\Users\`), por lo que un mismo archivo puede contar en ambas. La categoría dominante es AppData/usuarios con ~85% del total, lo cual es normal — los navegadores, actualizadores y aplicaciones de usuario escriben preferentemente en AppData.

**Patrones de interés:**

| Patrón | Cantidad | % | Nota |
|--------|----------|---|------|
| Archivos ejecutables (.exe, .dll, .bat, .ps1, etc.) | 347 | 5.1% | Merece revisión en contexto APT |
| Archivos ocultos (nombre con punto inicial) | 8 | 0.1% | Patrón Unix, inusual en Windows |
| Rutas completas >100 caracteres | 3,467 | 51.1% | Normal — rutas Windows profundas |

El 51.1% de rutas largas no es una señal de alerta: rutas como `C:\Users\gosta\AppData\Local\Microsoft\Windows\Caches\...` superan fácilmente los 100 caracteres. Los "nombres con espacios" se eliminaron de la tabla de patrones de interés — son inherentes al sistema de archivos Windows (`C:\Program Files\`, `C:\Windows Defender\`) y no aportan señal.

La creación de **264 DLLs** y **347 ejecutables** durante 72 minutos merece atención: mientras algunos son legítimos (actualizaciones, caché), en el contexto de una simulación APT podrían incluir payloads desplegados por el atacante.

## Paso 8: Evaluación de calidad de datos

**Operaciones del código**: el código itera sobre todas las columnas calculando `df[col].isnull().sum()` para construir un ranking de nulos ordenado por porcentaje descendente. Para los campos críticos (EventID, Computer, UtcTime, ProcessGuid, ProcessId), aplica umbrales: 0% → `GOOD`, <5% → `ISSUE`, ≥5% → `CRITICAL`. Para las consistencia, valida EventIDs contra un conjunto de valores conocidos (EIDs 1-25); valida el formato de todas las columnas GUID con la regex `r'^\{?[0-9a-fA-F]{8}-...\}?$'` (acepta formato con y sin llaves); y verifica que los PIDs sean positivos.

### 8a. Valores faltantes

Las 15 columnas con mayor porcentaje de nulos:

| Columna | Nulos | % | Motivo |
|---------|-------|---|--------|
| NewThreadId | 363,651 | 99.998% | Solo EID 8 (6 registros) |
| Hash | 363,642 | 99.996% | Solo EID 15 (15 registros) |
| PreviousCreationUtcTime | 363,445 | 99.942% | Solo EID 2 (212 registros) |
| CommandLine, ParentImage, etc. | 362,634 | 99.719% | Solo EID 1 (1,023 registros) |
| Device | 362,487 | 99.678% | Solo EID 9 (1,170 registros) |
| PipeName | 361,933 | 99.526% | Solo EID 17/18 (1,724 registros) |
| CreationUtcTime | 356,648 | 98.073% | Solo EID 2/11/15/23/24 |
| Campos de red | 349,233 | 96.034% | Solo EID 3 (14,424 registros) |

Estos porcentajes de nulos **no son un problema de calidad** — son consecuencia directa del diseño del CSV unificado. Cada columna solo tiene valores para los EventIDs que la utilizan.

### 8b. Campos críticos para análisis causal

El código evalúa cada campo filtrando por valores no nulos (`dropna()`), calcula el porcentaje de nulos sobre el total del dataset y asigna un estado descriptivo basado en lo que representan esos nulos.

| Campo | Nulos | % | Estado |
|-------|-------|---|--------|
| EventID | 0 | 0.00% | Sin nulos |
| Computer | 0 | 0.00% | Sin nulos |
| UtcTime | 2 | 0.00% | 2 nulos — EID 4/255 |
| ProcessGuid | 114,811 | 31.57% | Nulos por diseño — EID 8/10 |
| ProcessId | 114,811 | 31.57% | Nulos por diseño — EID 8/10 |

**Interpretación:** El marcado "CRITICAL" para ProcessGuid/ProcessId es un **falso positivo**. Los 114,811 registros sin ProcessGuid corresponden a EventIDs que usan nomenclatura diferente: EID 10 y 8 usan `SourceProcessGUID`/`TargetProcessGUID` en lugar de `ProcessGuid`, y EID 4 no tiene campos de proceso. La información de proceso sí está presente — solo con nombres de columna diferentes.

### 8c. Consistencia de datos

```
EventIDs inválidos:         1 registro (EventID 255)
GUIDs con formato inválido: 0 (validación corregida para soportar formato sin llaves)
PIDs inválidos:             0
```

**Hosts en el dataset:**

| Host | Registros | % |
|------|-----------|---|
| theblock.boombox.local | 149,254 | 41.0% |
| waterfalls.boombox.local | 145,217 | 39.9% |
| endofroad.boombox.local | 41,905 | 11.5% |
| diskjockey.boombox.local | 27,281 | 7.5% |

Los 4 hosts son exactamente los esperados para el entorno de laboratorio — sin hosts desconocidos ni valores anómalos en la columna `Computer`.

**Hallazgos:**
- **EventID 255** (1 registro) es un evento de error interno de Sysmon no documentado en la especificación oficial — hallazgo de calidad a nivel de formato.
- La validación de GUIDs reconoce el formato sin llaves (`44d66c27-4e6d-67da-...`) presente en este dataset, corrigiendo la regex original que solo aceptaba el formato `{...}`.

### 8d. Consistencia semántica de ProcessGuid

#### Procesos, PIDs y GUIDs en Sysmon

Antes de verificar la consistencia semántica, es necesario entender los dos mecanismos con los que Sysmon identifica procesos — y por qué uno de ellos es insuficiente para análisis forense.

**El problema: ambigüedad del PID.** Supongamos que `cmd.exe` se ejecuta con PID 4520, crea un archivo (EID 11), establece una conexión de red (EID 3), y luego termina (EID 5). Segundos después, el sistema operativo asigna PID 4520 a `svchost.exe`. Ahora aparecen nuevos eventos con PID 4520 — ¿pertenecen a `cmd.exe` o a `svchost.exe`? Sin más información, es imposible saberlo.

**PID (Process ID):** Entero asignado por el sistema operativo a cada proceso activo. Es único *solo mientras el proceso está vivo* — cuando termina, el OS recicla su número para nuevos procesos (ratio de reutilización confirmado en Paso 5). Consecuencia: los PIDs **no pueden identificar procesos de forma unívoca** a lo largo del tiempo.

**ProcessGuid (Globally Unique Identifier):** Sysmon genera un identificador único para cada *instancia* de proceso en el momento de su creación. El formato `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` codifica el GUID de la máquina, el timestamp de arranque del sistema, el PID y el timestamp de inicio del propio proceso — combinación que garantiza que **nunca se repite** ni entre reinicios ni entre máquinas. Un ProcessGuid nace con el proceso y muere con él: no se recicla.

**Ciclo de vida de un proceso en eventos Sysmon.** Un proceso genera múltiples eventos a lo largo de su existencia. El ProcessGuid es el hilo conductor que los une en una cadena causal:

```
    Proceso: cmd.exe
    GUID: {ABC-123}    PID: 4520

    EID 1  (Process Create)      ← GUID nace aquí
      │
      ├── EID 7  (Image Load)       carga DLLs
      ├── EID 11 (File Create)      crea archivo
      ├── EID 3  (Network Conn)     conecta a red
      │
    EID 5  (Process Terminate)   ← GUID muere aquí

    → Todos estos eventos comparten el mismo GUID {ABC-123}
    → Después de EID 5, el PID 4520 puede reutilizarse para otro proceso
      (con un GUID diferente)
```

**Por qué importa para análisis causal.** Si un ProcessGuid mapea a más de un PID o más de un ejecutable, la cadena causal se rompe: no podemos saber qué proceso generó qué evento. Las verificaciones siguientes comprueban exactamente esto.

```{dropdown} Modelo formal: eventos, procesos y relaciones causales
**Objetos fundamentales**

Sea $E$ el conjunto de todos los eventos (filas del CSV). Cada evento $e \in E$ expone los siguientes campos (posiblemente nulos según el EventID):

$$\text{computer}(e),\ \text{eid}(e),\ t(e) \quad \text{— siempre definidos}$$
$$\text{guid}(e),\ \text{pid}(e),\ \text{image}(e) \quad \text{— ProcessGuid, ProcessId, Image}$$
$$\text{parent_guid}(e) \quad \text{— ParentProcessGuid}$$
$$\text{source_guid}(e),\ \text{target_guid}(e) \quad \text{— SourceProcessGUID, TargetProcessGUID}$$

Sea $G$ el conjunto de GUIDs reales (no centinela) y $G^* = G \cup \{\emptyset\}$ el conjunto de todos los GUIDs observados, donde $\emptyset$ denota el GUID centinela `00000000-0000-0000-0000-000000000000`.

---

**Los cuatro pares GUID–PID–Image**

El esquema CSV registra cuatro columnas GUID, cada una con su PID e Image asociados y su dominio de EventIDs:

| $k$ | $g_k$ (GUID) | $p_k$ (PID) | $\text{img}_k$ (Image) | $D_k$ (EventIDs) |
|-----|--------------|-------------|------------------------|------------------|
| 1 | ProcessGuid | ProcessId | Image | EID $\notin$ \{8, 10\} |
| 2 | ParentProcessGuid | ParentProcessId | ParentImage | EID $= 1$ |
| 3 | SourceProcessGUID | SourceProcessId | SourceImage | EID $\in$ \{8, 10\} |
| 4 | TargetProcessGUID | TargetProcessId | TargetImage | EID $\in$ \{8, 10\} |

Para cada par $k$, la clase de equivalencia sobre los eventos de su dominio:

$$[g]_k = \{e \in E : \text{eid}(e) \in D_k \land g_k(e) = g\}, \quad g \in G^*$$

---

**Invariantes OS (restricciones sobre las clases)**

El axioma OS se generaliza a los cuatro pares y a todos los GUIDs observados — incluyendo el centinela:

$$\forall\, k,\ \forall\, g \in G^*,\ \forall\, e_1, e_2 \in [g]_k :\quad p_k(e_1) = p_k(e_2) \qquad \text{(Invariante 1)}$$

$$\forall\, k,\ \forall\, g \in G^*,\ \forall\, e_1, e_2 \in [g]_k :\quad \text{img}_k(e_1) = \text{img}_k(e_2) \qquad \text{(Invariante 2)}$$

Una violación $g \in V_{i,k}$ tiene distinto significado según el tipo de GUID:

- $g \in G$: error de registro — un proceso real aparece con PID o Image inconsistentes
- $g = \emptyset$: comportamiento esperado del centinela — múltiples procesos desconocidos comparten el placeholder, sus eventos son inrastreables

---

**Relación padre-hijo $R \subseteq G \times G$ (EID 1)**

$$(g_p,\, g_h) \in R \iff \exists\, e \in E :\ \text{eid}(e) = 1\ \land\ \text{guid}(e) = g_h\ \land\ \text{parent_guid}(e) = g_p$$

Propiedades: $R$ es una función parcial ($|{g_p : (g_p, g_h) \in R}| \leq 1$), sin ciclos — el grafo $(G, R)$ es un bosque. Consistencia temporal: $(g_p, g_h) \in R \Rightarrow t_{\text{birth}}(g_p) \leq t_{\text{birth}}(g_h)$.

La relación de ancestría $\rightarrow^*$ es el cierre transitivo de $R$: permite rastrear cadenas completas de spawning.

---

**Relación de acceso $A \subseteq G \times G$ (EID 8/10)**

$$(g_s,\, g_t) \in A \iff \exists\, e \in E :\ \text{eid}(e) \in \{8, 10\}\ \land\ \text{source_guid}(e) = g_s\ \land\ \text{target_guid}(e) = g_t$$

A diferencia de $R$, la relación $A$ es $n{:}m$, puede contener ciclos y sus nodos coexisten en el tiempo. Captura inyección de hilos (EID 8) y acceso a memoria (EID 10).

Asimetría del centinela: $\text{source_guid}$ es siempre conocido (Sysmon captura desde el lado del iniciador); $\text{target_guid}$ puede ser $\emptyset$ — el proceso víctima puede estar fuera de visibilidad.

---

**Grafo causal completo**

$$\mathcal{C} = (P,\ R \cup A)$$

donde $P = \{g \in G : \exists\, e \in E\ \text{con}\ \text{guid}(e) = g\}$ es el conjunto de instancias de proceso observadas.

$R$ aporta aristas de linaje (spawning); $A$ aporta aristas de acceso en runtime. Juntas describen la trayectoria completa de un ataque:

$$\text{cmd.exe} \xrightarrow{R} \text{powershell.exe} \xrightarrow{A} \text{lsass.exe}$$
```

#### Verificación de invariantes

Las verificaciones anteriores comprueban la validez *formal* de los datos (formatos, rangos). Las siguientes comprueban algo más profundo: **consistencia semántica**.

El punto de partida es una propiedad axiomática del sistema operativo: un proceso, durante toda su vida, tiene exactamente un PID (asignado en su creación, mantenido hasta su terminación) y exactamente una imagen ejecutable (el binario cargado en el `CreateProcess`). Ambos son inmutables mientras el proceso existe — no hay ningún mecanismo en Windows que permita a un proceso cambiar su PID o sustituir su ejecutable en tiempo de ejecución.

Si esto es cierto a nivel OS, debe reflejarse en el dataset: dado que el ProcessGuid identifica unívocamente una instancia de proceso, cada GUID real debería aparecer siempre asociado al mismo PID y al mismo ejecutable. Podemos verificarlo empíricamente buscando GUIDs que rompan esa propiedad. Cualquier violación no indica que el proceso se comportó de forma anómala — indica que el dato está mal registrado.

Esto requiere dos invariantes, aplicables a los cuatro pares GUID–PID e GUID–Image del esquema:

> **Invariante 1**: Un GUID → exactamente 1 PID (para su par correspondiente)
>
> **Invariante 2**: Un GUID → exactamente 1 Image (para su par correspondiente)

Las verificaciones incluyen el GUID centinela (`00000000-0000-0000-0000-000000000000`) — cualquier GUID que aparezca con múltiples PIDs o imágenes representa eventos problemáticos, sea real o centinela. El análisis detallado del centinela se aborda en el Paso 8e.

**Verificación 1: GUID → PID**

```{dropdown} Formalización
El Invariante 1 se verifica sobre los cuatro pares GUID–PID y sobre todos los GUIDs observados $G^*$. Para cada par $k$ y cada $g \in G^*$:

$$\text{pid_set}_k(g) = \{p_k(e) : e \in [g]_k,\ p_k(e) \neq \text{null}\}$$

El conjunto de violaciones del par $k$:

$$V_{1,k} = \{g \in G^* : |\text{pid_set}_k(g)| > 1\}$$

En este dataset, $V_{1,k} \cap G = \emptyset$ para todo $k$ — ningún GUID real viola el invariante. Solo el centinela $\emptyset$ aparece en $V_{1,k}$ (en $k=1,2,4$), lo que confirma que $p_k$ es una función bien definida sobre los GUIDs reales:

$$p_k : G \rightarrow \mathbb{N} \quad \text{(función bien definida para } g \in G\text{)}$$

Las violaciones del centinela no son errores de registro sino la consecuencia esperada de que múltiples procesos no identificables comparten el mismo placeholder.
```

**Operaciones del código**: para cada uno de los cuatro pares $(g_k, p_k)$, filtra el dataframe al dominio $D_k$, descarta filas con nulos en ambas columnas, y cuenta cuántos PIDs distintos aparecen para cada GUID — incluyendo el centinela. Cualquier GUID (real o centinela) que mapee a más de un PID es un evento problemático: no puede atribuirse unívocamente a un proceso.

```python
NULL_GUID = '00000000-0000-0000-0000-000000000000'

PAIRS = [
    (1, 'ProcessGuid',       'ProcessId',       'EID ∉ {8,10}'),
    (2, 'ParentProcessGuid', 'ParentProcessId', 'EID = 1'),
    (3, 'SourceProcessGUID', 'SourceProcessId', 'EID ∈ {8,10}'),
    (4, 'TargetProcessGUID', 'TargetProcessId', 'EID ∈ {8,10}'),
]

DOMAIN = {
    'ProcessGuid':       lambda d: d[~d['EventID'].isin([8, 10])],
    'ParentProcessGuid': lambda d: d[d['EventID'] == 1],
    'SourceProcessGUID': lambda d: d[d['EventID'].isin([8, 10])],
    'TargetProcessGUID': lambda d: d[d['EventID'].isin([8, 10])],
}

for k, guid_col, pid_col, domain_label in PAIRS:
    subset = DOMAIN[guid_col](df)
    valid  = subset[[guid_col, pid_col]].dropna()

    pids_per_guid = valid.groupby(guid_col)[pid_col].nunique()
    violations    = pids_per_guid[pids_per_guid > 1].sort_values(ascending=False)

    status = "✅ Sin violaciones" if len(violations) == 0 else f"⚠️  {len(violations)} GUID(s) con múltiples PIDs"
    print(f"\n  k={k}  {guid_col} / {pid_col}  [{domain_label}]")
    print(f"       GUIDs verificados        : {len(pids_per_guid):,}")
    print(f"       Resultado                : {status}")

    for guid, n_pids in violations.items():
        n_events = (valid[guid_col] == guid).sum()
        label = "  ← GUID centinela" if guid == NULL_GUID else ""
        print(f"       {guid}  →  {n_pids} PIDs distintos  ({n_events} eventos){label}")
```

```
  k=1  ProcessGuid / ProcessId  [EID ∉ {8,10}]
       GUIDs verificados        : 1,633
       Resultado                : ⚠️  1 GUID(s) con múltiples PIDs
       00000000-0000-0000-0000-000000000000  →  14 PIDs distintos  (36 eventos)  ← GUID centinela

  k=2  ParentProcessGuid / ParentProcessId  [EID = 1]
       GUIDs verificados        : 235
       Resultado                : ⚠️  1 GUID(s) con múltiples PIDs
       00000000-0000-0000-0000-000000000000  →  22 PIDs distintos  (500 eventos)  ← GUID centinela

  k=3  SourceProcessGUID / SourceProcessId  [EID ∈ {8,10}]
       GUIDs verificados        : 493
       Resultado                : ✅ Sin violaciones

  k=4  TargetProcessGUID / TargetProcessId  [EID ∈ {8,10}]
       GUIDs verificados        : 1,421
       Resultado                : ⚠️  1 GUID(s) con múltiples PIDs
       00000000-0000-0000-0000-000000000000  →  2 PIDs distintos  (4 eventos)  ← GUID centinela
```

El único GUID que viola el Invariante 1 es el **centinela** (`00000000-0000-0000-0000-000000000000`) — presente en k=1, k=2 y k=4. Ningún GUID real mapea a más de un PID. El centinela acumula **540 eventos** (36 + 500 + 4) que no pueden atribuirse a ningún proceso específico y quedan fuera del grafo causal. El par k=3 (`SourceProcessGUID`) es el único completamente limpio: el proceso que *inicia* un acceso siempre es identificable para Sysmon.

**Verificación 2: GUID → Image**

**Operaciones del código**: ídem a Verificación 1 pero sobre los pares GUID–Image. Normaliza las rutas a minúsculas antes de comparar (los paths Windows son case-insensitive). El escaneo rápido cubre los cuatro pares; el análisis detallado categoriza las violaciones de k=1.

```python
PAIRS_IMG = [
    (1, 'ProcessGuid',       'Image',       'EID ∉ {8,10}'),
    (2, 'ParentProcessGuid', 'ParentImage', 'EID = 1'),
    (3, 'SourceProcessGUID', 'SourceImage', 'EID ∈ {8,10}'),
    (4, 'TargetProcessGUID', 'TargetImage', 'EID ∈ {8,10}'),
]

for k, guid_col, img_col, domain_label in PAIRS_IMG:
    subset = DOMAIN[guid_col](df)
    valid  = subset[[guid_col, img_col]].dropna().copy()
    valid['img_norm'] = valid[img_col].str.lower()

    images_per_guid_k = valid.groupby(guid_col)['img_norm'].nunique()
    violations_k      = images_per_guid_k[images_per_guid_k > 1].sort_values(ascending=False)

    status = "✅ Sin violaciones" if len(violations_k) == 0 else f"⚠️  {len(violations_k)} GUID(s) con múltiples imágenes"
    print(f"\n  k={k}  {guid_col} / {img_col}  [{domain_label}]")
    print(f"       GUIDs verificados        : {len(images_per_guid_k):,}")
    print(f"       Resultado                : {status}")

    for guid, n_imgs in violations_k.items():
        n_events = (valid[guid_col] == guid).sum()
        label = "  ← GUID centinela" if guid == NULL_GUID else ""
        print(f"       {guid}  →  {n_imgs} imágenes distintas  ({n_events} eventos){label}")
```

```
  k=1  ProcessGuid / Image  [EID ∉ {8,10}]
       GUIDs verificados        : 1,633
       Resultado                : ⚠️  29 GUID(s) con múltiples imágenes
       00000000-0000-0000-0000-000000000000  →  8 imágenes distintas  (36 eventos)  ← GUID centinela
       [+ 28 GUIDs reales — detalle en análisis k=1 abajo]

  k=2  ParentProcessGuid / ParentImage  [EID = 1]
       GUIDs verificados        : 235
       Resultado                : ✅ Sin violaciones

  k=3  SourceProcessGUID / SourceImage  [EID ∈ {8,10}]
       GUIDs verificados        : 493
       Resultado                : ⚠️  2 GUID(s) con múltiples imágenes
       3fc4fefd-cf0d-67da-0900-000000004800  →  2 imágenes distintas  (67 eventos)
       4a85d404-cf08-67da-0900-000000005500  →  2 imágenes distintas  (292 eventos)

  k=4  TargetProcessGUID / TargetImage  [EID ∈ {8,10}]
       GUIDs verificados        : 1,421
       Resultado                : ⚠️  5 GUID(s) con múltiples imágenes
       00000000-0000-0000-0000-000000000000  →  2 imágenes distintas  (4 eventos)  ← GUID centinela
       2d5a9c51-5053-67da-2000-000000009000  →  2 imágenes distintas  (5 eventos)
       2d5a9c51-505c-67da-2500-000000009000  →  2 imágenes distintas  (288 eventos)
       3fc4fefd-5e35-67da-ff01-000000004800  →  2 imágenes distintas  (8 eventos)
       4a85d404-cf08-67da-0900-000000005500  →  2 imágenes distintas  (13 eventos)
```

**Resumen del escaneo:**

| Par | Violaciones | GUIDs reales | Centinela |
|-----|-------------|--------------|-----------|
| k=1 ProcessGuid / Image | 29 | 28 | ✅ (8 imágenes) |
| k=2 ParentProcessGuid / ParentImage | 0 | — | — |
| k=3 SourceProcessGUID / SourceImage | 2 | 2 | — |
| k=4 TargetProcessGUID / TargetImage | 5 | 4 | ✅ (2 imágenes) |

**k=2 completamente limpio** — cada GUID padre mapea siempre a la misma imagen. Coherente con el axioma OS: el proceso padre existe antes de generar hijos y no cambia su ejecutable.

**k=3 con 2 violaciones** — ambas son artefactos de boot: `csrss.exe` aparece con `<unknown process>` en 1–4 eventos de arranque. El mismo patrón que domina k=1.

**k=4 con 5 violaciones** (1 centinela + 1 artefacto boot + 3 genuinas) — las violaciones genuinas son `svchost.exe` vs `dxgiadaptercache.exe` (2 GUIDs, también presentes en k=1) y `OneDriveSetup.exe` vs `DllHost.exe` (1 GUID).

**Análisis detallado k=1: ProcessGuid → Image**

El notebook categoriza las 28 violaciones reales de k=1 por causa raíz:

| Categoría | GUIDs | Eventos | Acción |
|-----------|-------|---------|--------|
| Artefacto `<unknown process>` | 17 | 6,812 | Filtrar |
| Falso positivo por prefijo `\\?\` | 2 | 173 | Filtrar |
| Mismo binario, ruta diferente | 7 | 414 | Normalizar |
| Ejecutables diferentes (genuina) | 2 | 119 | Revisión manual |

**Artefactos `<unknown process>` (17 GUIDs):** Sysmon registra `<unknown process>` como Image cuando el proceso aún no está completamente inicializado (típico en procesos del sistema al arranque: `svchost.exe`, `services.exe`, `LogonUI.exe`). Incluye también los GUIDs del proceso System (PID 4), que aparece como `System` y `<unknown process>`.

**Falsos positivos `\\?\` (2 GUIDs):** El prefijo `\\?\` de Windows para rutas extendidas crea duplicados: `C:\Windows\System32\wbem\WMIADAP.exe` vs `\\?\C:\Windows\system32\wbem\WMIADAP.EXE` son el mismo archivo.

**Rutas diferentes al mismo binario (7 GUIDs):** Elastic Agent registra su ejecutable desde dos rutas según el contexto:

```
C:\Program Files\Elastic\Agent\elastic-agent.exe                                   ← symlink
C:\Program Files\Elastic\Agent\data\elastic-agent-8.17.0-96f2b9\elastic-agent.exe  ← ruta real
```

**Violaciones genuinas (2 GUIDs):** Dos ejecutables distintos (`svchost.exe` y `dxgiadaptercache.exe`) comparten ProcessGuid — una colisión real que corrompe las relaciones causales.

En total, **7,518 eventos** (2.07% del dataset) están afectados por estas 28 violaciones. Aunque las genuinas son solo 2 GUIDs (119 eventos), todas las categorías deben resolverse para garantizar la integridad del rastreo causal.

```{note}
Los scripts `find_processguid_pid_violations.py` y `find_processguid_image_violations.py` del directorio `pipeline/quality/` cubren únicamente el par k=1 (`ProcessGuid`). El análisis anterior extiende la verificación a los cuatro pares e identifica violaciones del Invariante 2 en k=3 y k=4 que los scripts actuales no detectan — estos hallazgos se analizan en las secciones **8e** (Invariante 1) y **8f** (Invariante 2).
```

### 8e. Análisis de violaciones — Invariante 1 (GUID → PID)

El Invariante 1 establece que cada GUID (real o centinela) debe mapear a exactamente un PID dentro de su dominio de EventIDs. Los resultados del escaneo revelan un patrón claro: **ningún GUID real viola el invariante en ningún par**. La única fuente de violaciones es el GUID centinela, que acumula eventos de múltiples procesos no identificables.

**Resumen por par:**

| Par | GUIDs verificados | Violaciones reales | Centinela | PIDs (centinela) | Eventos |
|-----|-------------------|--------------------|-----------|-----------------|---------|
| k=1 ProcessGuid / ProcessId | 1,633 | 0 | ✅ | 14 | 36 |
| k=2 ParentProcessGuid / ParentProcessId | 235 | 0 | ✅ | 22 | 500 |
| k=3 SourceProcessGUID / SourceProcessId | 493 | 0 | — | — | — |
| k=4 TargetProcessGUID / TargetProcessId | 1,421 | 0 | ✅ | 2 | 4 |

**Centinela en k=1 (ProcessGuid, 36 eventos)**

Los 36 eventos afectan a EIDs 3 (Network Connection), 7 (Image Load) y 13 (Registry Value Set) — procesos iniciados antes de la carga completa del driver Sysmon al inicio del sistema. Ninguno puede atribuirse a un proceso concreto; son 36 eslabones rotos en el grafo causal.

**Centinela en k=2 (ParentProcessGuid, 500 eventos)**

Es el par más afectado en número absoluto. Los 500 eventos EID 1 (Process Create) corresponden a procesos cuyos padres Sysmon no pudo identificar. La captura de run-01 se inició a las 05:00 UTC, coincidiendo con el arranque del sistema: los servicios Windows (svchost.exe, dllhost.exe, WmiPrvSE.exe) se lanzan en cascada durante el boot, antes de que el driver Sysmon alcance visibilidad completa del árbol de procesos.

```
run-01 (captura iniciada a las 05:00 UTC — arranque del sistema)
  Pico principal 05:00–05:05: ~330 procesos con padre centinela
  → Servicios del sistema inicializados en cascada al boot: svchost.exe (múltiples
    instancias), dllhost.exe, WmiPrvSE.exe — lanzados por services.exe antes de que
    el driver Sysmon tuviera visibilidad completa del árbol de procesos

  Segundo pico 05:35–05:40: ~90 procesos
  → Windows Task Scheduler dispara tareas de mantenimiento post-boot (actualización
    de caché WMI, limpieza de registro temporal)

run-02 (11:30 UTC, sistema estable): 8 filas — sin arranque en ventana de captura
run-18 (20:30 UTC): 67 filas dominadas por WmiPrvSE.exe — actividad WMI alta, sin boot
```

Esto resuelve la aparente anomalía del "padre con 500 hijos" identificada en el Paso 5b: el centinela agrupa los punteros de todos los padres no identificables, y los 500 registros EID 1 que apuntan a él son procesos legítimos del sistema lanzados durante el boot. De los 1,023 eventos EID 1, solo **523 tienen un `ParentProcessGuid` real y trazable**.

**k=3 completamente limpio**

El par SourceProcessGUID / SourceProcessId no registra ninguna violación. Esto es estructuralmente coherente: Sysmon captura los eventos EID 8 y 10 desde la perspectiva del proceso que inicia la acción, por lo que el proceso origen siempre es identificable.

**Centinela en k=4 (TargetProcessGUID, 4 eventos)**

Solo 4 eventos EID 10 (Process Access) tienen el centinela como TargetProcessGUID — el proceso receptor del acceso no pudo ser identificado. El patrón Source limpio / Target ocasionalmente centinela es estructural: el iniciador siempre es conocido porque el evento se registra desde su perspectiva; el receptor puede estar fuera del campo de visibilidad.

**Verificación cross-run (38 APT runs)**

| Par | Runs afectados | Eventos centinela por run (rango) |
|-----|----------------|----------------------------------|
| ProcessGuid | 38/38 (100%) | 12–439 |
| ParentProcessGuid | 24/38 (63%) | 2–500 |
| TargetProcessGUID | 22/38 (58%) | 4–71 |
| SourceProcessGUID | 8/38 (21%) | 2–5 |

ProcessGuid es el único par universalmente afectado. En todos los runs, GUIDs reales con múltiples PIDs = 0 — el Invariante 1 se cumple estrictamente sobre los GUIDs reales en toda la colección.

**Conclusión**: El Invariante 1 se verifica para todos los GUIDs reales. Los 540 eventos con GUID centinela (36 + 500 + 4) representan procesos no identificables — consecuencia estructural de la ventana temporal de captura, no errores del dataset. Estos eventos deben marcarse o excluirse antes de construir el grafo causal.

### 8f. Análisis de violaciones — Invariante 2 (GUID → Image)

El Invariante 2 establece que cada GUID debe mapear a exactamente una imagen ejecutable (comparación case-insensitive) dentro de su dominio. A diferencia del Invariante 1, este invariante revela **violaciones en GUIDs reales** en tres de los cuatro pares. El par k=2 es el único completamente limpio.

**Resumen por par:**

| Par | GUIDs verificados | Violaciones totales | GUIDs reales | Centinela |
|-----|-------------------|---------------------|--------------|-----------|
| k=1 ProcessGuid / Image | 1,633 | 29 | 28 | ✅ (8 imágenes) |
| k=2 ParentProcessGuid / ParentImage | 235 | 0 | 0 | — |
| k=3 SourceProcessGUID / SourceImage | 493 | 2 | 2 | — |
| k=4 TargetProcessGUID / TargetImage | 1,421 | 5 | 4 | ✅ (2 imágenes) |

**k=1 — 28 GUIDs reales**

Analizado en detalle en el Paso 8d. Las 28 violaciones se dividen en cuatro categorías:

| Categoría | GUIDs | Eventos | Acción |
|-----------|-------|---------|--------|
| Artefacto `<unknown process>` | 17 | 6,812 | Filtrar |
| Falso positivo `\\?\` | 2 | 173 | Filtrar |
| Mismo binario, ruta diferente | 7 | 414 | Normalizar |
| Genuina (ejecutables distintos) | 2 | 119 | Revisión manual |

7,518 eventos afectados (2.07% del dataset). Las categorías 1–3 son tratables automáticamente; las 2 violaciones genuinas requieren revisión manual.

**k=2 — Sin violaciones**

Cada GUID padre mapea siempre a la misma imagen. Coherente con el axioma OS: un proceso no sustituye su ejecutable durante su vida, y EID 1 captura invariablemente el mismo ejecutable en todos los eventos donde aparece como padre.

**k=3 — 2 GUIDs con múltiples imágenes [nuevo hallazgo]**

Dos GUIDs de proceso origen en EID 8/10 aparecen con `SourceImage` distintas:

| GUID | `<unknown process>` | Imagen real | Eventos |
|------|---------------------|-------------|---------|
| `3fc4fefd-cf0d-67da-0900-000000004800` | 1 | `csrss.exe` (66) | 67 |
| `4a85d404-cf08-67da-0900-000000005500` | 4 | `csrss.exe` (288) | 292 |

La inspección de las imágenes revela el patrón: en ambos GUIDs, la mayoría de eventos registran correctamente `csrss.exe` como `SourceImage`, pero 1–4 eventos de arranque registran `<unknown process>`. Es el mismo artefacto de boot que domina k=1 — el proceso no estaba completamente inicializado cuando Sysmon capturó esos primeros eventos. No hay variantes de ruta ni colisión genuina de ejecutables.

**k=4 — 5 GUIDs con múltiples imágenes [nuevo hallazgo]**

Cinco GUIDs de proceso destino en EID 8/10 aparecen con `TargetImage` distintas. La inspección permite categorizarlos:

| GUID | Imágenes | Eventos | Categoría |
|------|----------|---------|-----------|
| `00000000-0000-0000-0000-000000000000` | `taskhostw.exe` / `wermgr.exe` | 4 | Centinela (esperado) |
| `4a85d404-cf08-67da-0900-000000005500` | `<unknown process>` (1) / `csrss.exe` (12) | 13 | Artefacto boot |
| `2d5a9c51-5053-67da-2000-000000009000` | `svchost.exe` (7) / `dxgiadaptercache.exe` (47) | 54 | **Genuina** |
| `2d5a9c51-505c-67da-2500-000000009000` | `svchost.exe` (286) / `dxgiadaptercache.exe` (2) | 288 | **Genuina** |
| `3fc4fefd-5e35-67da-ff01-000000004800` | `OneDriveSetup.exe` (1) / `DllHost.exe` (7) | 8 | **Genuina** |

Los dos GUIDs de `svchost.exe` / `dxgiadaptercache.exe` aparecen también en k=1 con la misma inconsistencia — el mismo proceso es destino de accesos inter-proceso con imagen inconsistente en el CSV, y también genera eventos EID ∉ {8,10} con la misma imagen inconsistente. Son las únicas 2 violaciones genuinas de k=1 que se propagan a k=4.

**Anomalía cross-par: GUID `4a85d404-cf08-67da-0900-000000005500`**

Este GUID aparece como violación en k=3 (origen, 292 eventos) y k=4 (destino, 13 eventos). En ambos roles la violación es el mismo artefacto: `<unknown process>` en los primeros eventos de boot del proceso `csrss.exe`. No es una colisión genuina — es el mismo patrón de arranque documentado en k=1.

**Cobertura de los scripts actuales del pipeline**

Los scripts `find_processguid_pid_violations.py` y `find_processguid_image_violations.py` del directorio `pipeline/quality/` verifican únicamente el par k=1. Las violaciones de k=3 y k=4 quedan **fuera de su alcance**. El Script 4 (`4_sysmon_data_cleaner.py`) también cubre solo k=1. El paso **8g** extiende la detección de violaciones PID a los cuatro pares directamente en el notebook y genera la versión completa del archivo `04_processguid-pid-violations-run-01.csv`.

### 8g. Volcado de violaciones PID — extensión a todos los pares k

Los pasos 8d y 8e mostraron que el Invariante 1 (GUID → PID) solo presenta violaciones en el GUID centinela, distribuidas en tres de los cuatro pares k. El archivo `04_processguid-pid-violations-run-01.csv` generado por el script del pipeline recoge únicamente k=1 (14 filas). Este paso extiende la detección a los cuatro pares y genera la versión completa del archivo.

**Violaciones esperadas:**

| Par | GUID(s) violadores | Filas en CSV |
|-----|-------------------|--------------|
| k=1 `ProcessGuid` / `ProcessId` | centinela (14 PIDs) | 14 |
| k=2 `ParentProcessGuid` / `ParentProcessId` | centinela (22 PIDs) | 22 |
| k=3 `SourceProcessGUID` / `SourceProcessId` | — | 0 |
| k=4 `TargetProcessGUID` / `TargetProcessId` | centinela (2 PIDs) | 2 |
| **Total** | | **38** |

**Algoritmo en tres fases**

*Fase 1 — Definición de pares y dominios de EventID*

La lista `PAIRS` codifica las cuatro triplas `(guid_col, pid_col, img_col)` y `DOMAIN_FN` define el filtro de EventID para cada par:

```python
PAIRS = [
    (1, 'ProcessGuid',       'ProcessId',       'Image'),
    (2, 'ParentProcessGuid', 'ParentProcessId', 'ParentImage'),
    (3, 'SourceProcessGUID', 'SourceProcessId', 'SourceImage'),
    (4, 'TargetProcessGUID', 'TargetProcessId', 'TargetImage'),
]

DOMAIN_FN = {
    'ProcessGuid':       lambda d: d[~d['EventID'].isin([8, 10])],
    'ParentProcessGuid': lambda d: d[d['EventID'] == 1],
    'SourceProcessGUID': lambda d: d[d['EventID'].isin([8, 10])],
    'TargetProcessGUID': lambda d: d[d['EventID'].isin([8, 10])],
}
```

*Fase 2 — Detección de GUIDs con múltiples PIDs*

Para cada par, se filtra `df` al dominio del par, se cuentan los PIDs únicos por GUID y se identifican los violadores. `.drop_duplicates()` garantiza una fila por combinación única `(GUID, PID, Image, Computer)` — no una fila por evento:

```python
pids_per_guid   = valid.groupby(guid_col)[pid_col].nunique()
violating_guids = pids_per_guid[pids_per_guid > 1].index

viol_rows = (valid[valid[guid_col].isin(violating_guids)]
             [[guid_col, pid_col, img_col, 'Computer']]
             .drop_duplicates()
             .rename(columns={guid_col: 'ProcessGuid', pid_col: 'ProcessId', img_col: 'Image'}))
```

*Fase 3 — Ensamblado con metadatos y volcado*

Las filas de los cuatro pares se apilan en un único DataFrame. Las columnas `k_pair`, `guid_col` y `pid_col` permiten al paso de extracción posterior saber sobre qué columna del CSV Sysmon aplicar el join para cada grupo de violaciones:

```python
viol_rows = viol_rows.assign(k_pair=k, guid_col=guid_col, pid_col=pid_col)

df_pid_viol = pd.concat(violations).sort_values(['k_pair', 'ProcessGuid', 'ProcessId'])
df_pid_viol.to_csv(output_path, index=False)
```

**Código completo (celda 8g del notebook):**

```python
from pathlib import Path

PAIRS = [
    (1, 'ProcessGuid',       'ProcessId',       'Image'),
    (2, 'ParentProcessGuid', 'ParentProcessId', 'ParentImage'),
    (3, 'SourceProcessGUID', 'SourceProcessId', 'SourceImage'),
    (4, 'TargetProcessGUID', 'TargetProcessId', 'TargetImage'),
]

DOMAIN_FN = {
    'ProcessGuid':       lambda d: d[~d['EventID'].isin([8, 10])],
    'ParentProcessGuid': lambda d: d[d['EventID'] == 1],
    'SourceProcessGUID': lambda d: d[d['EventID'].isin([8, 10])],
    'TargetProcessGUID': lambda d: d[d['EventID'].isin([8, 10])],
}

violations = []

for k, guid_col, pid_col, img_col in PAIRS:
    subset = DOMAIN_FN[guid_col](df)
    valid  = subset[[guid_col, pid_col, img_col, 'Computer']].dropna(subset=[guid_col, pid_col])

    pids_per_guid   = valid.groupby(guid_col)[pid_col].nunique()
    violating_guids = pids_per_guid[pids_per_guid > 1].index

    if len(violating_guids) == 0:
        print(f'k={k}  {guid_col} / {pid_col}: ✅ sin violaciones')
        continue

    viol_rows = (valid[valid[guid_col].isin(violating_guids)]
                 [[guid_col, pid_col, img_col, 'Computer']]
                 .drop_duplicates()
                 .rename(columns={guid_col: 'ProcessGuid', pid_col: 'ProcessId', img_col: 'Image'})
                 .assign(k_pair=k, guid_col=guid_col, pid_col=pid_col))

    violations.append(viol_rows)
    print(f'k={k}  {guid_col} / {pid_col}: ⚠️  {len(violating_guids)} GUID(s) → {len(viol_rows)} filas')

if violations:
    df_pid_viol = (pd.concat(violations, ignore_index=True)
                   .sort_values(['k_pair', 'ProcessGuid', 'ProcessId'])
                   .reset_index(drop=True))

    output_path = Path('../dataset/run-01-apt-1/04_processguid-pid-violations-run-01.csv')
    df_pid_viol.to_csv(output_path, index=False)

    print(f'\n✅ Guardado: {output_path}  ({len(df_pid_viol)} filas totales)')
    display(df_pid_viol)
else:
    print('\n✅ Sin violaciones PID en ningún par k')
```

## Conclusiones

El análisis de calidad del CSV Sysmon de run-01-apt-1 revela un dataset **apto para análisis de seguridad**, con las siguientes características clave:

1. **Integridad estructural**: 363,657 registros, 20 EventIDs, 45 columnas, 100% de cobertura temporal. Los altos porcentajes de nulos son un artefacto del diseño CSV unificado, no un problema de calidad.

2. **Consistencia temporal**: Ventana de 72 minutos (05:00-06:12 UTC) con tasa media de 84 eventos/segundo. Ráfagas significativas (pico de 30,563 eventos/minuto) sugieren períodos de actividad intensa.

3. **Identificadores de proceso fiables**: 1,632 GUIDs reales con 1,240 PIDs distintos. PID reuse confirmado (ratio 1.32), reforzando la necesidad de usar GUIDs para rastreo causal en lugar de PIDs.

4. **Indicadores de actividad APT detectados**:
   - `SystemFailureReporter.exe` en `C:\Users\Public\` (implante sospechoso, 31 procesos hijos)
   - Puertos no estándar 444, 6001, 81 (posibles canales C2)
   - PowerShell ExecutionPolicy Bypass, comandos de descarga
   - 44.5% de tráfico hacia IPs públicas

5. **Invariante 1 (GUID → PID) verificado en los cuatro pares**: ningún GUID real viola el invariante. El único violador es el GUID centinela (∅ = `00000000-0000-0000-0000-000000000000`), que acumula 540 eventos inrastreables: 36 en k=1, 500 en k=3, 4 en k=4. Son artefactos de boot esperados, no errores de datos.

6. **Invariante 2 (GUID → Image) requiere corrección selectiva**:
   - **k=1** (ProcessGuid): 28 GUIDs con múltiples imágenes — 17 `<unknown process>` (boot), 7 rutas Elastic Agent (variantes de versión), 2 prefijo `\\?\` (normalizables), 2 colisiones genuinas (svchost/dxgiadaptercache; OneDriveSetup/DllHost).
   - **k=2** (ParentProcessGuid): sin violaciones — datos limpios.
   - **k=3** (SourceProcessGUID): 2 GUIDs violadores, ambos artefactos de boot (`<unknown process>` para csrss.exe) — no son colisiones genuinas.
   - **k=4** (TargetProcessGUID): 5 GUIDs violadores — GUID centinela (∅), 1 artefacto de boot, y 3 colisiones genuinas (los mismos svchost/dxgiadaptercache de k=1 más OneDriveSetup/DllHost).

**Puntos clave:**
- El dataset es **apto para análisis causal** tras resolver las violaciones de Image: 28 en k=1 (automatizable con Script 4) y 3 genuinas en k=4 (requiere extensión del pipeline a los cuatro pares GUID).
- Los artefactos de boot (`<unknown process>`, GUID centinela ∅) son fenómenos inevitables de Sysmon — deben filtrarse, no corregirse.
- Los indicadores de APT detectados (SystemFailureReporter.exe, puerto 444, PowerShell Bypass) confirman que la simulación generó artefactos realistas de ataque.
- La combinación de GUIDs fiables + cobertura temporal completa + diversidad de EventIDs proporciona los tres pilares necesarios para el análisis de cadenas causales.

## Actividad Práctica

### Ejercicio: Exploración profunda y corrección de violaciones

Los ejercicios siguientes se ejecutan en el notebook `8_sysmon_csv_exploratory_analysis.ipynb` usando el DataFrame `df` ya cargado, y en la terminal usando el script `9_sysmon_data_cleaner.py` desde la carpeta `sesion-2/`.

**Parte A: Anatomía del GUID centinela (Invariante 1)**

El GUID centinela ∅ (`00000000-0000-0000-0000-000000000000`) viola el Invariante 1 en k=1 (36 eventos, 14 PIDs) y en k=3 (500 eventos). Ejecuta el siguiente código y responde las preguntas:

```python
NULL_GUID = '00000000-0000-0000-0000-000000000000'

# Eventos del centinela en k=1 (dominio: EID ∉ {8, 10})
s_k1 = df[~df['EventID'].isin([8, 10]) & (df['ProcessGuid'] == NULL_GUID)]
print(f"k=1 → {len(s_k1)} eventos, {s_k1['ProcessId'].nunique()} PIDs, "
      f"{s_k1['Image'].nunique()} Images, "
      f"Computers: {s_k1['Computer'].unique()}")
print(s_k1['EventID'].value_counts())

# Eventos del centinela en k=3 (dominio: EID ∈ {8, 10})
s_k3 = df[df['EventID'].isin([8, 10]) & (df['SourceProcessGUID'] == NULL_GUID)]
print(f"\nk=3 → {len(s_k3)} eventos, {s_k3['SourceProcessId'].nunique()} PIDs, "
      f"{s_k3['SourceImage'].nunique()} Images")
print(s_k3['SourceImage'].value_counts().head(5))
```

- ¿El centinela tiene una `Image` consistente en k=1? ¿Y en k=3?
- ¿Por qué k=3 acumula ~14× más eventos que k=1 para el mismo GUID centinela?

**Parte B: Reglas de corrección por categoría (Invariante 2, k=1)**

Los 28 GUIDs violadores de k=1 se agrupan en 4 categorías. Para cada una, analiza su corrección:

1. **`<unknown process>` (17 GUIDs)**: Escoge uno de los GUIDs con esta violación y examina todos sus eventos. ¿El GUID tiene una Image "real" dominante? ¿Cuántos eventos tienen `<unknown process>` vs la Image real?

   ```python
   # Ejemplo: primer GUID con <unknown process>
   guid = '<uno de los 17 GUIDs del Paso 8f>'
   eventos = df[~df['EventID'].isin([8,10]) & (df['ProcessGuid'] == guid)]
   print(eventos['Image'].value_counts())
   ```

2. **Prefijo `\\?\` (2 GUIDs)**: La corrección es automática — eliminar el prefijo. Escribe la expresión pandas que aplicarías sobre la columna `Image`.

3. **Elastic Agent (7 GUIDs)**: Los 7 GUIDs aparecen con rutas de instalación distintas (versión real vs symlink). ¿La diferencia de ruta implica una diferencia funcional (distinto binario)? ¿Cuál ruta elegirías como canónica y por qué?

4. **Colisiones genuinas (2 GUIDs)**: svchost/dxgiadaptercache y OneDriveSetup/DllHost comparten GUID. Estas no tienen corrección automática — requieren decisión del analista. En el archivo de violaciones (`04_sysmon-run-01-violations.csv`), ¿qué columnas adicionales examinarías para decidir qué Image y qué ProcessGuid asignar?

**Parte C: Verificación del archivo de violaciones PID extendido**

Tras ejecutar la celda 8g del notebook, verifica que el archivo generado coincide con los hallazgos del paso 8e:

```python
import pandas as pd

pid_v = pd.read_csv('../dataset/run-01-apt-1/'
                    '04_processguid-pid-violations-run-01.csv')

print("Violaciones PID por par k:")
print(pid_v.groupby(['k_pair', 'guid_col', 'pid_col'])
      .agg(GUIDs=('ProcessGuid', 'nunique'), filas=('ProcessGuid', 'count'))
      .to_string())

NULL_GUID = '00000000-0000-0000-0000-000000000000'
print(f"\nTotal filas: {len(pid_v)}")
print(f"GUID centinela presente: {NULL_GUID in pid_v['ProcessGuid'].values}")
```

- ¿Los totales de GUIDs y filas por par k coinciden con lo esperado según el paso 8e?
- El par k=3 no tiene filas en el CSV. ¿Qué propiedad del dominio de k=3 (`SourceProcessGUID`) explica que no haya violaciones del Invariante 1?

### Resultado esperado

Al finalizar esta sección, deberías comprender:
- Cómo evaluar la calidad de un dataset de seguridad distinguiendo artefactos de diseño de problemas reales.
- Los indicadores de actividad APT presentes en los datos y su significancia para la detección.
- Por qué los GUIDs son esenciales para el rastreo causal y los PIDs son insuficientes.
- Cómo detectar violaciones semánticas de ProcessGuid (GUID→PID, GUID→Image), clasificarlas por causa raíz y diseñar estrategias de corrección — automáticas para artefactos de ruta y boot, con revisión humana para colisiones genuinas.

En la **Sesión 2 / Sección 9**, aplicaremos las correcciones identificadas aquí usando el script `9_sysmon_data_cleaner.py` en modo interactivo completo.

### Entrega

Sube tu notebook o scripts completados al siguiente Google Drive:

📁 [Carpeta de entregas — Sección 8](https://drive.google.com/drive/folders/1BqPQo_xX1Ud7Vib37roVwyx7JuCk3uhw?usp=sharing)

Instrucciones:
1. Entra al Drive con tu cuenta institucional.
2. Crea una carpeta con tu nombre completo usando guiones bajos como separador (ej. `Juan_Garcia_Lopez`).
3. Deposita tu notebook dentro de esa carpeta.
