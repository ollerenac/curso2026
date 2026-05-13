# Violaciones en Contexto: Invariante 1 y Recuperación de GUIDs

**Duración**: 60 minutos

```{admonition} Dataset de trabajo
:class: note

Descarga el dataset desde [Google Drive](https://drive.google.com/drive/folders/1bLbcxM_mRAaeHIGTIy3PnAEOz0EcUMhA?usp=sharing).
Archivos necesarios: `02_sysmon-run-01.csv`, `04_sysmon-run-01-violations.csv`,
`04_processguid-pid-violations-run-01.csv`.
Notebook de trabajo: `9_violaciones_en_contexto.ipynb`.
```

## Contexto

La sección 8 detectó y catalogó las violaciones de las invariantes de ProcessGuid.
Esta sección se concentra en la **Invariante 1** — la única cuya validez quedó
empíricamente confirmada por los datos de `run-01-apt-1`:

> **Invariante 1:** para todo GUID real generado por Sysmon, existe exactamente
> un `ProcessId` en un `Computer` dado.

La Invariante 2 (unicidad de `Image` por GUID) **no se tratará aquí** — el análisis
de la sección 8 reveló violaciones que no son artefactos recuperables, lo que indica
que la propiedad debe reformularse antes de implementar correcciones. Queda pendiente
para una sección posterior.

```{admonition} Resultado clave de la sección 8
:class: important

El único violador de la Invariante 1 es el **GUID centinela**
`∅ = 00000000-0000-0000-0000-000000000000`.
Todos los GUIDs reales generados por Sysmon tienen exactamente un PID.
El centinela acumula **36 eventos en k=1**, **500 en k=2** y **2 en k=4**.
```

---

## Formulación matemática: recuperación de GUID

### Variables y notación

Sea $\mathcal{E}$ el conjunto completo de eventos del CSV `02_sysmon-run-01.csv`.
Cada evento $e \in \mathcal{E}$ es una fila con columnas; denotamos
$e.\text{Col}$ el valor de la columna `Col` en el evento $e$.

Las variables principales son:

| Símbolo | Significado |
|---------|-------------|
| $c$ | Identificador de máquina — valor de la columna `Computer` (ej. `endofroad.boombox.local`) |
| $p$ | Identificador de proceso en ejecución — valor entero de una columna `*ProcessId` |
| $g$ | Identificador de instancia de proceso — UUID de 36 caracteres de una columna `*ProcessGuid` |
| $\emptyset$ | GUID centinela: `00000000-0000-0000-0000-000000000000` |
| $\text{EID}(e)$ | EventID del evento $e$ — entero que identifica el tipo de evento Sysmon |

### Los cuatro dominios de observación (k-pairs)

La sección 8 definió cuatro pares de columnas (GUID, PID) válidos en subconjuntos
distintos del dataset. Cada k-pair define un **dominio de observación**
$\mathcal{E}_k \subseteq \mathcal{E}$:

$$
\mathcal{E}_1 = \{e \in \mathcal{E} : \text{EID}(e) \notin \{8, 10\}\}
\quad \text{(todos excepto CreateRemoteThread y ProcessAccess)}
$$

$$
\mathcal{E}_2 = \{e \in \mathcal{E} : \text{EID}(e) = 1\}
\quad \text{(ProcessCreate — eventos de creación de proceso)}
$$

$$
\mathcal{E}_3 = \mathcal{E}_4 = \{e \in \mathcal{E} : \text{EID}(e) \in \{8, 10\}\}
\quad \text{(CreateRemoteThread y ProcessAccess)}
$$

En cada dominio, un proceso $(p, c)$ puede ser observable desde un ángulo distinto:
como proceso activo (k=1), como proceso padre que lanzó un hijo (k=2),
como proceso origen de una inyección (k=3), o como proceso objetivo de un acceso (k=4).

### Función de observación por k-pair

Para el proceso identificado por el par $(p, c)$, definimos el conjunto de GUIDs
que cada k-pair asocia a ese proceso:

$$
\mathcal{G}_1(p,\, c) = \bigl\{\, e.\text{ProcessGuid}
    \;:\; e \in \mathcal{E}_1,\; e.\text{Computer} = c,\; e.\text{ProcessId} = p \bigr\}
$$

$$
\mathcal{G}_2(p,\, c) = \bigl\{\, e.\text{ParentProcessGuid}
    \;:\; e \in \mathcal{E}_2,\; e.\text{Computer} = c,\; e.\text{ParentProcessId} = p \bigr\}
$$

$$
\mathcal{G}_3(p,\, c) = \bigl\{\, e.\text{SourceProcessGUID}
    \;:\; e \in \mathcal{E}_3,\; e.\text{Computer} = c,\; e.\text{SourceProcessId} = p \bigr\}
$$

$$
\mathcal{G}_4(p,\, c) = \bigl\{\, e.\text{TargetProcessGUID}
    \;:\; e \in \mathcal{E}_4,\; e.\text{Computer} = c,\; e.\text{TargetProcessId} = p \bigr\}
$$

Cada $\mathcal{G}_k(p, c)$ es un **conjunto** (sin repeticiones) de GUIDs.
Puede estar vacío si el proceso $(p, c)$ no tiene ningún evento en el dominio $\mathcal{E}_k$.
Puede contener $\emptyset$ si Sysmon registró el proceso sin GUID real.
Puede contener uno o más GUIDs reales.

### Conjunto de GUIDs reales observados

Reunimos todas las observaciones de los cuatro k-pairs y **excluimos el centinela**:

$$
\mathcal{G}(p,\, c) \;=\; \left(\bigcup_{k=1}^{4} \mathcal{G}_k(p,\, c)\right) \setminus \{\emptyset\}
$$

El operador $\bigcup$ es la **unión de conjuntos**: $\mathcal{G}(p,c)$ contiene todos
los GUIDs reales que aparecen en cualquiera de los cuatro k-pairs para ese proceso.
El operador $\setminus \{\emptyset\}$ es la **diferencia de conjuntos**: elimina el
centinela del resultado para que no "recuperemos" un evento centinela con otro centinela.

### Regla de recuperación

El cardinal $|\mathcal{G}(p,c)|$ — el número de GUIDs reales distintos observados
para el proceso $(p,c)$ — determina la acción de corrección:

| $|\mathcal{G}(p,c)|$ | Interpretación | Acción |
|----------------------|----------------|--------|
| $= 1$ | $\mathcal{G}(p,c) = \{g_0\}$: un único GUID real observado | `REPLACE_GUID`: asignar $g_0$ al evento centinela |
| $> 1$ | Múltiples GUIDs reales: probable **reuso de PID** entre instancias distintas del mismo número de proceso | `REVIEW`: ordenar por tiempo y desambiguar manualmente |
| $= 0$ | Ningún GUID real en ningún k-pair: el proceso nunca tuvo visibilidad real de Sysmon | `BOOT_ARTIFACT`: excluir de cadenas causales |

---

## Enfoque A: búsqueda restringida a k=1

El primer enfoque de recuperación busca el GUID correcto consultando únicamente
$\mathcal{G}_1(p, c)$: para cada evento centinela, se busca un EID=1 con el mismo
`Computer` y `ProcessId` con timestamp anterior o igual al del evento centinela.

**Resultado sobre los 36 eventos centinela de k=1:**

| Acción | Eventos | % |
|--------|---------|---|
| `REPLACE_GUID` | 2 | 6 % |
| `BOOT_ARTIFACT` | 34 | 94 % |

Solo el 6 % de los eventos centinela tiene un EID=1 candidato visible desde k=1.
El 94 % son artefactos de boot donde el proceso nunca emitió un EID=1 con GUID real.

El producto de este enfoque está en `09_sentinel_k1_enfoque_A.csv`.

---

## Enfoque B: búsqueda cruzada por todos los k-pairs

El Enfoque B aplica la fórmula completa $\mathcal{G}(p,c)$: para cada evento
centinela de k=1, computa la unión de GUIDs reales observados en los cuatro k-pairs.
Esto captura evidencia de GUID que el Enfoque A ignora:

- Un proceso que nunca emitió un EID=1 propio puede aparecer como **padre** (k=2)
  en el EID=1 de uno de sus procesos hijos — ese EID=1 del hijo registra el
  `ParentProcessGuid` del proceso buscado.
- Un proceso puede aparecer como **origen** (k=3) o **destino** (k=4) de una
  inyección, donde el GUID sí fue capturado correctamente.

La investigación procede evento por evento: para cada uno de los 36 PIDs centinela,
se construye $\mathcal{G}(p,c)$ y se evalúa la regla de recuperación.

```{admonition} Caso de estudio: evento 1 de 36
:class: tip

El primer evento centinela (fila 5976) corresponde a:
- `Computer`: `endofroad.boombox.local`
- `ProcessId`: 3364
- `EventID`: 3 (NetworkConnect → 10.1.0.4:135, protocolo RPC)
- `Image`: `<unknown process>`
- `ts`: 2025-03-19 05:01:15 UTC

La investigación busca $\mathcal{G}(3364,\, \texttt{endofroad})$ consultando
los cuatro k-pairs en el CSV completo.
```

---

## Actividad Práctica

### Ejercicio: Implementación de $\mathcal{G}(p,c)$ y aplicación a los 36 eventos

Trabaja en el notebook `9_violaciones_en_contexto.ipynb` en la sección **Enfoque B**.

**Paso 1 — Construir la tabla de GUIDs reales por k-pair**

Para el caso de estudio (PID 3364 en `endofroad`), extrae manualmente los GUIDs
observados en cada $\mathcal{G}_k$:

```python
c, p = 'endofroad.boombox.local', 3364.0

g1 = set(df[~df['EventID'].isin([8,10]) &
            (df['Computer']==c) & (df['ProcessId']==p)
           ]['ProcessGuid'].dropna()) - {NULL_GUID}

g2 = set(df[(df['EventID']==1) &
            (df['Computer']==c) & (df['ParentProcessId']==p)
           ]['ParentProcessGuid'].dropna()) - {NULL_GUID}

g3 = set(df[df['EventID'].isin([8,10]) &
            (df['Computer']==c) & (df['SourceProcessId']==p)
           ]['SourceProcessGUID'].dropna()) - {NULL_GUID}

g4 = set(df[df['EventID'].isin([8,10]) &
            (df['Computer']==c) & (df['TargetProcessId']==p)
           ]['TargetProcessGUID'].dropna()) - {NULL_GUID}

G = g1 | g2 | g3 | g4   # unión de los cuatro k-pairs
print(f'G({p}, {c}) = {G}')
print(f'|G| = {len(G)}')
```

**Paso 2 — Generalizar a los 36 eventos centinela**

Implementa la función `compute_G(df, p, c)` que devuelve $\mathcal{G}(p,c)$
y aplícala a los 36 eventos del catálogo `sentinel_k1`. Genera el archivo
`09_sentinel_k1_enfoque_B.csv` con el mismo esquema que el Enfoque A.

**Paso 3 — Comparación de enfoques**

Une ambos archivos por `_original_row_index` y responde:
- ¿Cuántos eventos adicionales recupera el Enfoque B respecto al A?
- ¿Coinciden los GUIDs candidatos donde ambos enfoques recuperan el mismo evento?
- ¿Qué k-pair aporta más evidencia en los casos nuevos recuperados por B?

### Entrega

📁 [Carpeta de entregas — Sección 9](https://drive.google.com/drive/folders/1BqPQo_xX1Ud7Vib37roVwyx7JuCk3uhw?usp=sharing)

1. Entra al Drive con tu cuenta institucional.
2. Crea una carpeta con tu nombre completo (ej. `Juan_Garcia_Lopez`).
3. Deposita el notebook con el nombre: `apellido_nombre_sesion2_ej4.ipynb`
