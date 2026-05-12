# Violaciones en Contexto: Anatomía y Corrección

**Duración**: 45 minutos

```{admonition} Dataset de trabajo
:class: note

Descarga el dataset de la sección 8 desde [Google Drive](https://drive.google.com/drive/folders/1bLbcxM_mRAaeHIGTIy3PnAEOz0EcUMhA?usp=sharing).
Los archivos necesarios ya están generados: `02_sysmon-run-01.csv` y `04_sysmon-run-01-violations.csv`.
```

## Contexto

La sección 8 detectó y catalogó las violaciones de las dos invariantes de ProcessGuid. La sección 10 aplicará el pipeline de corrección automatizado. Esta sección cubre el espacio intermedio: **¿qué aspecto tienen esas violaciones en los datos reales?**

Antes de corregir automáticamente, el investigador necesita entender:
- Qué eventos rodean a una violación (contexto temporal)
- Por qué ocurre la inconsistencia en ese punto del tiempo
- Qué información está disponible para tomar la decisión de corrección correcta

Esto es especialmente crítico para las violaciones genuinas — aquellas donde no hay una regla automática obvia y el analista debe decidir manualmente qué valor es el correcto.

## Invariante 1 en contexto: el GUID centinela

El GUID centinela ∅ (`00000000-0000-0000-0000-000000000000`) viola el Invariante 1 en k=1 con **36 eventos y 14 PIDs distintos**. Estos 36 eventos son procesos del sistema que Sysmon no pudo atribuir a ningún GUID real durante el arranque.

¿Qué aspecto tienen en el CSV? El código siguiente carga el archivo de violaciones, localiza el primer evento centinela de k=1 y muestra los 15 eventos anteriores y posteriores en el CSV original:

```python
import pandas as pd
from pathlib import Path

NULL_GUID = '00000000-0000-0000-0000-000000000000'

# Cargar el CSV de violaciones (con _original_row_index)
viol = pd.read_csv('../dataset/run-01-apt-1/04_sysmon-run-01-violations.csv',
                   low_memory=False)

# Parsear timestamp (unix ms, filtrar sentinelas negativos)
df['ts'] = pd.to_datetime(df['timestamp'].where(df['timestamp'] > 0), unit='ms')
viol['ts'] = pd.to_datetime(viol['timestamp'].where(viol['timestamp'] > 0), unit='ms')

# Eventos centinela en k=1 (EID ∉ {8, 10}), ordenados por posición en CSV
sentinel_k1 = (viol[~viol['EventID'].isin([8, 10]) & (viol['ProcessGuid'] == NULL_GUID)]
               .sort_values('_original_row_index'))

print(f"Eventos centinela en k=1: {len(sentinel_k1)}")
print(f"PIDs distintos: {sentinel_k1['ProcessId'].nunique()}")
print(f"Rango temporal: {sentinel_k1['ts'].min()} → {sentinel_k1['ts'].max()}")
sentinel_k1[['ts', 'EventID', 'ProcessGuid', 'ProcessId', 'Image', 'Computer']].head(10)
```

### Ventana de contexto: primer evento centinela

```python
# Posición en el CSV original del primer evento centinela
first = sentinel_k1.iloc[0]
idx   = int(first['_original_row_index'])

WINDOW = 15  # eventos antes y después

# Extraer ventana del DataFrame completo (ya ordenado cronológicamente)
window = df.iloc[max(0, idx - WINDOW) : idx + WINDOW + 1].copy()
window['▶'] = ''
window.loc[idx, '▶'] = '◀ violación'

cols = ['▶', 'ts', 'EventID', 'ProcessGuid', 'ProcessId', 'Image', 'Computer']
display(window[cols].reset_index(drop=True))
```

**¿Qué observar?**
- Los eventos inmediatamente anteriores tienen GUIDs reales — el driver ya estaba funcionando.
- El evento centinela interrumpe la secuencia: Sysmon registra el evento pero no tiene GUID disponible.
- Los eventos posteriores retoman GUIDs reales: el driver recuperó visibilidad.

Este patrón es consistente con el análisis de 8e: el centinela aparece en ráfagas durante el boot (05:00–05:05 UTC) y en picos de actividad WMI post-boot.

## Invariante 2 en contexto: colisión genuina

La colisión genuina de k=1 identificada en 8f involucra dos GUIDs donde `svchost.exe` y `dxgiadaptercache.exe` comparten ProcessGuid. Con **119 eventos** y **2 GUIDs** afectados, es la violación que más compromete el rastreo causal.

### Ciclo de vida completo del GUID violador

```python
# GUIDs con colisión genuina (identificados en 8f)
# Ajusta estos valores con los GUIDs reales encontrados en tu análisis
genuine_guid_1 = '2d5a9c51-5053-67da-2000-000000009000'
genuine_guid_2 = '2d5a9c51-505c-67da-2500-000000009000'

# Todos los eventos de ese GUID, ordenados por timestamp
guid_events = (df[~df['EventID'].isin([8, 10]) & df['ProcessGuid'].isin([genuine_guid_1])]
               .copy()
               .sort_values('ts'))

print(f"Total eventos para el GUID: {len(guid_events)}")
print(f"\nDistribución por Image:")
print(guid_events['Image'].value_counts())
print(f"\nDistribución por EventID:")
print(guid_events['EventID'].value_counts().sort_index())

cols = ['ts', 'EventID', 'ProcessGuid', 'ProcessId', 'Image', 'Computer']
display(guid_events[cols])
```

### Ventana alrededor del cambio de Image

El punto crítico es el momento exacto donde la `Image` cambia de `svchost.exe` a `dxgiadaptercache.exe`. Ese es el evento que rompe el Invariante 2:

```python
# Encontrar el primer evento con Image distinta a la mayoritaria
dominant_image = guid_events['Image'].mode()[0]
change_rows = guid_events[guid_events['Image'] != dominant_image]

if len(change_rows) > 0:
    change_idx = int(change_rows.iloc[0]['_original_row_index'])
    window = df.iloc[max(0, change_idx - WINDOW) : change_idx + WINDOW + 1].copy()
    window['▶'] = ''
    window.loc[change_idx, '▶'] = '◀ Image cambia aquí'
    display(window[['▶', 'ts', 'EventID', 'ProcessGuid', 'ProcessId', 'Image', 'Computer']]
            .reset_index(drop=True))
```

**¿Qué observar?**
- Los eventos anteriores al cambio registran `svchost.exe`.
- El evento de cambio registra `dxgiadaptercache.exe` con el mismo GUID.
- ¿Comparten el mismo `ProcessId`? ¿O el PID también cambia? Si el PID cambia con la Image, sugiere una colisión de GUID entre dos procesos distintos — el caso más difícil de resolver.

## Invariante 2 en contexto: artefacto `<unknown process>`

Los 17 GUIDs con artefacto `<unknown process>` son más fáciles de entender visualmente. El patrón es siempre el mismo: pocos eventos iniciales con `<unknown process>` seguidos de todos los eventos restantes con la Image real.

```python
# Tomar el primer GUID con artefacto <unknown process> de las violaciones de Image
img_viol = pd.read_csv('../dataset/run-01-apt-1/'
                       '04_processguid-image-violations-run-01.csv')

unknown_guids = img_viol[img_viol['Image'] == '<unknown process>']['ProcessGuid'].unique()
guid_unknown  = unknown_guids[0]

guid_ev = (df[~df['EventID'].isin([8, 10]) & (df['ProcessGuid'] == guid_unknown)]
           .copy()
           .sort_values('ts'))

print(f"GUID: {guid_unknown}")
print(f"Distribución de Image:")
print(guid_ev['Image'].value_counts())
print(f"\nCronología (primeros 10 eventos):")
display(guid_ev[['ts', 'EventID', 'Image', 'ProcessId', 'Computer']].head(10))
```

Este patrón confirma la regla de corrección automática: para los GUIDs de esta categoría, se reemplaza `<unknown process>` con la Image dominante del mismo GUID.

## ¿Cuándo intervenir manualmente?

La inspección contextual permite clasificar cada violación en una de tres decisiones:

| Categoría | Evidencia visual | Decisión |
|-----------|-----------------|----------|
| Artefacto boot (`<unknown process>`) | Pocos eventos iniciales con imagen desconocida, luego imagen real dominante | Reemplazar automáticamente con imagen dominante |
| Prefijo `\\?\` | Misma ruta con y sin prefijo, mismo PID | Normalizar automáticamente |
| Elastic Agent (variante de ruta) | Dos rutas distintas pero mismo binario (distinta versión) | Elegir ruta canónica (real sobre symlink) |
| Colisión genuina | Image cambia a mitad del ciclo de vida, PID posiblemente distinto | Revisión manual: separar en GUIDs distintos |

La sección 10 implementa el pipeline completo que aplica las correcciones automáticas (categorías 1–3) y genera el archivo de violaciones para revisión manual (categoría 4).

## Actividad Práctica

### Ejercicio: Inspección de violaciones reales

Completa las siguientes exploraciones en el notebook `9_violaciones_en_contexto.ipynb`. El notebook ya carga `df` y `viol` con el parseo de timestamps correcto.

**Parte A: Centinela en k=2**

El centinela acumula 500 eventos en k=2 (`ParentProcessGuid`). A diferencia de k=1 (36 eventos dispersos), estos 500 corresponden a procesos lanzados durante el boot. Adapta el código de la ventana de contexto para el primer evento centinela de k=2 y responde:

- ¿Qué EventID tienen estos eventos? (Pista: k=2 es dominio EID=1)
- ¿Cuántos procesos distintos (por `Image`) tienen al centinela como padre?
- ¿En qué ventana temporal ocurren la mayoría? ¿Coincide con el pico de 05:00–05:05 descrito en 8e?

**Parte B: Inspección manual de una colisión genuina**

Para los GUIDs con colisión genuina de k=1 (`svchost.exe` / `dxgiadaptercache.exe`):

1. ¿El `ProcessId` es el mismo en todos los eventos del GUID, o cambia cuando cambia la `Image`?
2. ¿Qué EventIDs están presentes antes del cambio y después?
3. Basándote en lo observado: ¿se trata de un único proceso que cambió su ejecutable (imposible en Windows), o de dos procesos distintos que colisionaron en el mismo GUID?
4. ¿Qué columnas adicionales del CSV (`ParentProcessGuid`, `ParentImage`, `CommandLine`) ayudarían a decidir cuál GUID es el correcto para cada proceso?

**Parte C: Regla de corrección para `<unknown process>`**

Implementa la función de corrección automática para la categoría `<unknown process>`:

```python
def fix_unknown_process(df, guid):
    """
    Para el GUID dado, reemplaza '<unknown process>' en la columna Image
    con la Image dominante del mismo GUID (la que más aparece).
    Retorna el número de filas corregidas.
    """
    mask   = (~df['EventID'].isin([8, 10])) & (df['ProcessGuid'] == guid)
    events = df[mask]

    real_images  = events[events['Image'] != '<unknown process>']['Image']
    if real_images.empty:
        return 0

    dominant = real_images.mode()[0]
    unknown_mask = mask & (df['Image'] == '<unknown process>')
    df.loc[unknown_mask, 'Image'] = dominant
    return unknown_mask.sum()

# Prueba con el primer GUID de la categoría unknown_process
n_fixed = fix_unknown_process(df, guid_unknown)
print(f"Filas corregidas: {n_fixed}")
print(df[~df['EventID'].isin([8,10]) & (df['ProcessGuid'] == guid_unknown)]['Image'].value_counts())
```

¿La función funciona correctamente? ¿Qué pasaría si un GUID tiene `<unknown process>` en todos sus eventos (no hay imagen dominante)?

### Entrega

Sube tu notebook o scripts completados al siguiente Google Drive:

📁 [Carpeta de entregas — Sección 9](https://drive.google.com/drive/folders/1BqPQo_xX1Ud7Vib37roVwyx7JuCk3uhw?usp=sharing)

Instrucciones:
1. Entra al Drive con tu cuenta institucional.
2. Crea una carpeta con tu nombre completo usando guiones bajos como separador (ej. `Juan_Garcia_Lopez`).
3. Deposita tu notebook con el nombre: `apellido_nombre_sesion2_ej4.ipynb`
