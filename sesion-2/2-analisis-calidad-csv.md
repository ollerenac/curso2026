# Análisis de Calidad del CSV Sysmon

**Duración**: 60 minutos

## Contexto: ¿Por qué analizar la calidad del CSV?

En la sección anterior convertimos los datos Sysmon de formato JSONL a un CSV tabular de 45 columnas usando el Script 2. Ahora tenemos un archivo CSV con un esquema unión que abarca los 22 tipos de EventID.

Pero antes de usar estos datos para construir un sistema de detección de intrusiones, necesitamos responder: **¿los datos tienen la calidad suficiente para alimentar algoritmos de análisis causal?** Este análisis cubre distribución de eventos, patrones temporales, relaciones entre procesos, actividad de red/archivos, y una evaluación de "readiness" algorítmica.

```{tip}
El código de esta sección se puede ejecutar paso a paso en el notebook `2c-sysmon-csv-exploratory-analysis.ipynb`, que contiene el análisis completo con visualizaciones interactivas.
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
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
  │ Paso 8:     │   │ Paso 9:      │   │ Paso 10:     │
  │ Evaluación  │──►│ Readiness    │──►│ Reporte      │
  │ de calidad  │   │ algorítmica  │   │ resumen      │
  └─────────────┘   └──────────────┘   └──────────────┘
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

**Observaciones:**

- Los **4 EventIDs dominantes** (10, 12, 7, 13) concentran el 89.96% del dataset — actividad de fondo típica de servidores Windows (acceso entre procesos, operaciones de registro, carga de librerías).
- **EventID 255** es un evento no estándar de Sysmon con un solo registro. Este valor no está documentado en la especificación oficial de Sysmon y merece investigación — podría ser un error de parsing, un evento de error de Sysmon, o un artefacto del preprocesamiento.
- Comparando con el análisis de consistencia (notebook 2b, 200K muestras), los porcentajes relativos se mantienen consistentes, confirmando que el muestreo del 55% fue representativo.
- Los eventos de alto valor para detección de amenazas (**EID 1** Process Create, **EID 3** Network Connection, **EID 8** Create Remote Thread) representan solo el 4.25% del total, pero contienen la información más relevante para análisis de cadenas causales.

## Paso 4: Análisis temporal

El CSV no tiene una columna `UtcTime` directa, pero contiene `timestamp` — un epoch en milisegundos (int64) con cobertura del 100%. La conversión es directa:

```python
df['UtcTime'] = pd.to_datetime(df['timestamp'], unit='ms')
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
- Solo **2 registros** carecen de timestamp tras la conversión — probablemente los eventos EID 4 (Sysmon State Change) y EID 255 (Unknown), que pueden tener timestamps en formato no estándar.

**Patrones temporales (visualizaciones):**

```
Pico de eventos por minuto:     30,563
Promedio de eventos por minuto:  4,981.6
Hora más activa:  05:00 UTC (305,542 eventos)
Hora menos activa: 06:00 UTC (58,113 eventos)
```

El notebook genera 4 visualizaciones adaptadas a la ventana de 72 minutos:

1. **Timeline acumulativa** — Línea que muestra la acumulación de eventos. Cambios de pendiente revelan períodos de actividad intensa vs calma.
2. **Histograma de eventos/minuto** — Distribución de las tasas por minuto con líneas de media y mediana. El pico de 30,563 vs media de ~5,000 confirma ráfagas significativas.
3. **Tasa por EventID (top 5)** — Líneas separadas para los 5 EventIDs más frecuentes en ventanas de 1 minuto. Permite identificar qué tipos de eventos generan las ráfagas.
4. **Tasa general (1 minuto)** — Área sombreada mostrando la intensidad de actividad a lo largo del tiempo con la media como referencia.

**Puntos clave:**
- La ventana de **72 minutos** confirma que el dataset captura un período específico de ejecución del escenario APT, no una monitorización continua — cada evento en esta ventana es potencialmente relevante.
- La tasa de 84 eventos/segundo con picos de 30,563/minuto indica **ráfagas de actividad** que podrían corresponder a fases específicas del ataque (ejecución, movimiento lateral, exfiltración).
- Solo 2 registros sin timestamp (0.0005%) representan una tasa de integridad temporal excepcional para un dataset de esta escala.
- El epoch en milisegundos (`timestamp`) proporciona la **misma resolución temporal** que el dominio NetFlow, habilitando la correlación cruzada en la Sesión 3.

## Paso 5: Análisis de relaciones entre procesos

Los eventos Sysmon identifican procesos mediante dos mecanismos complementarios: **GUIDs** (identificadores globales únicos por instancia de proceso) y **PIDs** (identificadores numéricos reutilizables por el sistema operativo). Analizar ambos revela la fiabilidad de cada uno para rastreo causal.

**Pares GUID/PID en el dataset:**

| Par de columnas | Pares válidos | GUIDs únicos | PIDs únicos | Combinaciones | PID reuse |
|-----------------|---------------|--------------|-------------|---------------|-----------|
| ProcessGuid / ProcessId | 248,846 | 1,632 | 1,240 | 1,632 | 1.32 ⚠️ |
| ParentProcessGuid / ParentProcessId | 1,023 | 235 | 242 | 256 | 1.06 |
| SourceProcessGUID / SourceProcessId | 114,742 | 493 | 447 | 493 | 1.10 ⚠️ |
| TargetProcessGUID / TargetProcessId | 114,742 | 1,421 | 1,143 | 1,422 | 1.24 ⚠️ |

**Interpretación:**

- **PID reuse confirmado** en 3 de 4 pares (ratio > 1.1). El par ProcessGuid/ProcessId muestra el ratio más alto (1.32): 1,632 instancias de proceso únicas comparten solo 1,240 PIDs. Esto significa que ~30% de los PIDs fueron reutilizados por procesos diferentes durante la ventana de 72 minutos.
- **GUIDs son el identificador confiable**: El número de GUIDs únicos coincide exactamente con el número de combinaciones GUID-PID (1,632 = 1,632), confirmando que cada GUID identifica una instancia de proceso única. En contraste, los PIDs son ambiguos.
- **ParentProcess** solo tiene 1,023 pares válidos — exclusivamente de EventID 1 (Process Create), el único tipo de evento que registra información del proceso padre.
- **Source/Target** tienen 114,742 pares — de EventIDs 8 (Create Remote Thread) y 10 (Process Access), que modelan interacciones entre dos procesos.

**Implicación para algoritmos causales**: Cualquier algoritmo de análisis causal **debe usar GUIDs, no PIDs**, para rastrear procesos. Usar PIDs produciría falsos positivos por reutilización.

### 5b. Análisis de creación de procesos (EventID 1)

```
Eventos de creación de procesos:    1,023
Con relación padre-hijo válida:     1,023 (100%)
Procesos huérfanos (sin padre):     0
```

**Estadísticas de procesos padre:**

| Métrica | Valor |
|---------|-------|
| Padres únicos con hijos | 235 |
| Promedio de hijos por padre | 4.4 |
| Máximo hijos de un solo padre | 500 |
| Padres con >10 hijos | 9 |

**Top 5 procesos padre más prolíficos:**

| Hijos | Proceso padre |
|-------|---------------|
| 500 | *No encontrado en el dataset* |
| 44 | *No encontrado en el dataset* |
| 31 | `C:\Users\Public\SystemFailureReporter.exe` |
| 19 | *No encontrado en el dataset* |
| 19 | `C:\Program Files\Google\Chrome\Application\chrome.exe` |

**Hallazgos de seguridad:**

- **"Parent not found in dataset"** significa que el proceso padre fue creado *antes* del inicio de la ventana de captura (05:00 UTC). Su GUID existe en los registros EID 1 de sus hijos, pero no hay un evento EID 1 propio en el dataset. El padre con 500 hijos es probablemente `svchost.exe` o `services.exe`.
- **`SystemFailureReporter.exe`** en `C:\Users\Public\` es altamente sospechoso: un ejecutable con nombre engañoso ubicado en una carpeta pública (accesible por cualquier usuario). Con 31 procesos hijos, es consistente con un implante de la simulación APT.
- **Chrome con 19 hijos** es comportamiento normal — cada pestaña y extensión genera procesos hijos.

### 5c. Análisis de líneas de comando (EventID 1)

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

## Paso 6: Actividad de red

El análisis de EventID 3 (Network Connection) examina 14,424 conexiones de red capturadas durante la ventana de 72 minutos.

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
- El 44.5% de tráfico hacia IPs públicas es significativo para un entorno corporativo cerrado y sugiere actividad de C2 o exfiltración.

## Paso 7: Actividad del sistema de archivos

El análisis combina EventID 11 (File Create) y EventID 23 (File Delete):

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

**Patrones sospechosos:**

| Patrón | Cantidad | % |
|--------|----------|---|
| Archivos ejecutables (.exe, .dll, .bat, .ps1, etc.) | 347 | 5.1% |
| Archivos ocultos | 8 | 0.1% |
| Nombres largos (>100 chars) | 3,467 | 51.1% |
| Nombres con espacios | 2,834 | 41.8% |

La creación de **264 DLLs** y **347 ejecutables** durante 72 minutos merece atención: mientras algunos son legítimos (actualizaciones, caché), en el contexto de una simulación APT podrían incluir payloads desplegados por el atacante.

## Paso 8: Evaluación de calidad de datos

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

| Campo | Nulos | % | Estado |
|-------|-------|---|--------|
| EventID | 0 | 0.00% | ✅ GOOD |
| Computer | 0 | 0.00% | ✅ GOOD |
| UtcTime | 2 | 0.00% | ⚠️ ISSUE |
| ProcessGuid | 114,811 | 31.57% | ❌ CRITICAL |
| ProcessId | 114,811 | 31.57% | ❌ CRITICAL |

**Interpretación:** El marcado "CRITICAL" para ProcessGuid/ProcessId es un **falso positivo**. Los 114,811 registros sin ProcessGuid corresponden a EventIDs que usan nomenclatura diferente: EID 10 y 8 usan `SourceProcessGUID`/`TargetProcessGUID` en lugar de `ProcessGuid`, y EID 4 no tiene campos de proceso. La información de proceso sí está presente — solo con nombres de columna diferentes.

### 8c. Consistencia de datos

```
EventIDs inválidos:       1 registro (EventID 255)
Timestamps inválidos:     2 registros (0.0%)
GUIDs con formato inválido: 0 (validación corregida para soportar formato sin llaves)
PIDs inválidos:           0
```

La validación de GUIDs ahora reconoce correctamente el formato sin llaves (`44d66c27-4e6d-67da-...`) presente en este dataset, tras corregir la expresión regular original que solo aceptaba GUIDs con llaves (`{...}`).

**Puntos clave:**
- Los altos porcentajes de nulos (hasta 99.998%) **no son un defecto de calidad** — son una consecuencia directa del diseño CSV unificado donde cada fila solo usa las columnas de su EventID.
- El marcado "CRITICAL" para ProcessGuid (31.57% nulos) es un **falso positivo del scoring**: los registros sin ProcessGuid son EID 8/10 que usan `SourceProcessGUID`/`TargetProcessGUID`. La información de proceso está presente, solo con nomenclatura diferente.
- **EventID 255** (1 registro) es el único hallazgo genuino de calidad — un evento no documentado en la especificación oficial de Sysmon que requiere investigación.
- La validación de GUIDs sin llaves demuestra la importancia de adaptar las reglas de validación al dataset real, no a la especificación teórica.

## Paso 9: Evaluación de readiness algorítmica

Esta evaluación mide si los datos son aptos para alimentar un algoritmo de búsqueda de cadenas causales, puntuando la presencia de columnas críticas:

**Evaluación por categoría:**

| Categoría | Columnas | Resultado |
|-----------|----------|-----------|
| **Core** | EventID (100% ✅), Computer (100% ✅), UtcTime (100% ✅) | 3/3 |
| **Process Tracking** | ProcessGuid (68.4% ⚠️), ProcessId (68.4% ⚠️), ParentProcessGuid (0.3% ❌), ParentProcessId (0.3% ❌) | 1/4 |
| **Inter-Process** | SourceProcessGUID (31.6% ❌), TargetProcessGUID (31.6% ❌), SourceProcessId (31.6% ❌), TargetProcessId (31.6% ❌) | 0/4 |
| **Command Analysis** | CommandLine (0.3% ❌), Image (68.4% ⚠️) | 0.5/2 |
| **File Operations** | TargetFilename (4.7% ❌) | 0/1 |

```
Puntuación total:   4.5 / 14 (32.1%)
Estado:             🔴 POOR - Major data quality issues
```

**¿Es realmente "POOR"?** No — esta puntuación es **engañosa** y revela una limitación del método de evaluación, no del dataset. El scoring asume que todas las columnas deberían estar pobladas globalmente, pero en un CSV unificado por diseño:

- **ParentProcessGuid** (0.3%) solo existe en EID 1 — pero tiene 100% de cobertura *dentro* de EID 1.
- **CommandLine** (0.3%) solo existe en EID 1 — con 100% de cobertura interna.
- **SourceProcessGUID** (31.6%) solo existe en EID 8 y 10 — con 100% de cobertura interna.

El algoritmo de cadenas causales no necesita que *todos* los registros tengan CommandLine — solo necesita que *los registros de EID 1* lo tengan. Y lo tienen al 100%.

**Verificaciones positivas:**

```
✅ CommandLine coverage en EID 1: 100.0%
✅ GUID naming consistente (4 columnas)
✅ Cobertura temporal: 100.0%
✅ Diversidad de eventos: 20 EventIDs
```

**Recomendación**: Un scoring más apropiado evaluaría la cobertura de cada campo *dentro de su EventID correspondiente*, no globalmente. Esa evaluación (realizada en la sección de consistencia estructural) confirmó 100% de campos presentes para todos los 19 EventIDs estándar.

## Paso 10: Reporte resumen

El notebook genera un reporte JSON (`sysmon_csv_analysis_summary.json`) en el directorio del dataset con todas las métricas consolidadas. Del reporte se extrae la **distribución por host** no mostrada en secciones anteriores:

| Host | Registros | % |
|------|-----------|---|
| theblock.boombox.local | 149,254 | 41.0% |
| waterfalls.boombox.local | 145,217 | 39.9% |
| endofroad.boombox.local | 41,905 | 11.5% |
| diskjockey.boombox.local | 27,281 | 7.5% |

Los dos hosts principales (theblock y waterfalls) concentran el 81% de la actividad, mientras que diskjockey (controlador de dominio con DNS) genera solo el 7.5%.

## Conclusiones

El análisis de calidad del CSV Sysmon de run-01-apt-1 revela un dataset **apto para análisis de seguridad**, con las siguientes características clave:

1. **Integridad estructural**: 363,657 registros, 20 EventIDs, 45 columnas, 100% de cobertura temporal. Los altos porcentajes de nulos son un artefacto del diseño CSV unificado, no un problema de calidad.

2. **Consistencia temporal**: Ventana de 72 minutos (05:00-06:12 UTC) con tasa media de 84 eventos/segundo. Ráfagas significativas (pico de 30,563 eventos/minuto) sugieren períodos de actividad intensa.

3. **Identificadores de proceso confiables**: Los GUIDs proporcionan identificación unívoca (1,632 procesos únicos). PID reuse confirmado (ratio 1.32), reforzando la necesidad de usar GUIDs para rastreo causal.

4. **Indicadores de actividad APT detectados**:
   - `SystemFailureReporter.exe` en `C:\Users\Public\` (implante sospechoso, 31 procesos hijos)
   - Puertos no estándar 444, 6001, 81 (posibles canales C2)
   - PowerShell ExecutionPolicy Bypass, comandos de descarga
   - 44.5% de tráfico hacia IPs públicas

5. **Readiness para algoritmos causales**: La puntuación global de 32.1% es engañosa — la cobertura *por EventID* es del 100% para todos los campos. El dataset está listo para análisis causal siempre que el algoritmo consulte los campos correctos para cada tipo de evento.

**Puntos clave:**
- El dataset es **apto para análisis causal** a pesar de la puntuación de readiness de 32.1% — la cobertura *por EventID* es del 100% para todos los campos relevantes.
- Los indicadores de APT detectados (SystemFailureReporter.exe, puerto 444, PowerShell Bypass) confirman que la simulación generó artefactos realistas de ataque.
- La combinación de GUIDs confiables + cobertura temporal completa + diversidad de EventIDs proporciona los tres pilares necesarios para el análisis de cadenas causales.

## Actividad Práctica

### Ejercicio: Interpretación Crítica de la Calidad de Datos

Responde las siguientes preguntas basándote en el análisis de calidad:

1. **¿Por qué la puntuación de readiness algorítmica de 32.1% es engañosa?** Diseña un método de scoring alternativo que evalúe la cobertura de campos *dentro de cada EventID* en lugar de globalmente. ¿Qué puntuación obtendría el dataset con tu método?

2. **EventID 1 (Process Create) representa solo el 0.28% del dataset (1,023 eventos), pero es el EventID con más campos (23).** ¿Por qué es desproporcionadamente importante para el análisis de amenazas? Piensa en qué información exclusiva aporta (CommandLine, ParentImage, ParentProcessGuid).

3. **El análisis de red muestra 1,378 conexiones al puerto 444, que no es un servicio estándar.** Formula una hipótesis de seguridad: ¿qué tipo de actividad APT podría explicar este tráfico? Considera la proximidad al puerto 443 (HTTPS) y el contexto de la simulación de ataque.

4. **El PID reuse ratio es 1.32 para ProcessGuid/ProcessId.** Diseña una prueba de validación que demuestre por qué usar PIDs (en lugar de GUIDs) para rastreo causal produciría falsos positivos. Describe los datos de entrada y el resultado esperado.

5. **Si tuvieras que elegir solo 5 columnas como "mínimo viable" para entrenar un modelo IDS**, ¿cuáles elegirías y por qué? Considera: identificación del evento, contexto temporal, identificación de proceso, y actividad observable.

### Resultado esperado

Al finalizar esta sección, deberías comprender:
- Cómo evaluar la calidad de un dataset de seguridad distinguiendo artefactos de diseño de problemas reales.
- La importancia de la evaluación *por EventID* frente a la evaluación global en un CSV unificado.
- Los indicadores de actividad APT presentes en los datos y su significancia para la detección.
- Por qué los GUIDs son esenciales para el rastreo causal y los PIDs son insuficientes.

En la **Sesión 3**, usaremos este dataset validado para la **correlación cruzada entre dominios** (Sysmon y NetFlow), aplicando los Scripts 5 y 6 del pipeline para vincular actividad de procesos con flujos de red.
