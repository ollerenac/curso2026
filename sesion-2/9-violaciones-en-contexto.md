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
| $t(e)$ | Timestamp del evento $e$ — milisegundos Unix, columna `timestamp` |

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
centinela del resultado para que no se recupere un evento centinela con otro centinela.

### Regla de recuperación

El cardinal $\lvert\mathcal{G}(p,c)\rvert$ — el número de GUIDs reales distintos observados
para el proceso $(p,c)$ — determina la acción de corrección:

| Cardinalidad $\lvert\mathcal{G}(p,c)\rvert$ | Interpretación | Acción |
|----------------------------------------------|----------------|--------|
| $= 1$ | $\mathcal{G}(p,c) = \{g_0\}$: un único GUID real observado | `REPLACE_GUID` (ver nota de ambigüedad) |
| $> 1$ | Múltiples GUIDs reales: probable **reuso de PID** entre instancias distintas del mismo número de proceso | `REVIEW`: ordenar por tiempo y desambiguar |
| $= 0$ | Ningún GUID real en ningún k-pair: el proceso nunca tuvo visibilidad real de Sysmon | `BOOT_ARTIFACT`: excluir de cadenas causales |

### Nota de ambigüedad en el caso $\lvert\mathcal{G}\rvert = 1$

La acción `REPLACE_GUID` no puede demostrarse correcta con certeza absoluta desde los
datos solos. La asignación $g_0 \to e^*$ es una **inferencia de máxima verosimilitud**
que descansa sobre el siguiente supuesto no verificable:

> **Supuesto de observabilidad:** toda instancia de proceso con PID $p$ en Computer $c$
> deja al menos un evento con GUID real en alguno de los cuatro k-pairs.

Si este supuesto no se cumple — porque existió una segunda instancia del proceso cuya
existencia completa quedó documentada únicamente mediante eventos centinela — entonces
$\lvert\mathcal{G}\rvert = 1$ y sin embargo $g_0$ no sería el GUID correcto para $e^*$.

**Verificación temporal como evidencia adicional.** Sea:

$$
t_{\min}(g_0) = \min_{e \,:\, e.\text{ProcessGuid}=g_0} t(e)
\qquad
t_{\max}(g_0) = \max_{e \,:\, e.\text{ProcessGuid}=g_0} t(e)
$$

Si el timestamp del evento centinela $t^*$ cumple:

$$
t_{\min}(g_0) \;\leq\; t^* \;\leq\; t_{\max}(g_0)
$$

el centinela cae dentro del ciclo de vida conocido de $g_0$, lo que constituye
evidencia fuerte (aunque no concluyente) de que la asignación es correcta.

Si en cambio $t^* > t_{\max}(g_0)$, el evento centinela ocurre **después** del último
evento conocido de $g_0$, señal de posible reuso de PID aun cuando $\lvert\mathcal{G}\rvert = 1$,
y la acción recomendada pasa a `REVIEW`.

La regla completa para el caso $\lvert\mathcal{G}\rvert = 1$ queda entonces:

$$
\text{acción}(e^*, g_0) =
\begin{cases}
\texttt{REPLACE\_GUID} & \text{si } t_{\min}(g_0) \leq t^* \leq t_{\max}(g_0) \\
\texttt{REVIEW}        & \text{si } t^* > t_{\max}(g_0)
\end{cases}
$$
