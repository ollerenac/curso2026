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

**Verificación temporal como evidencia adicional.**

Primero definimos el **conjunto de ciclo de vida** de $g_0$: todos los eventos del
dataset donde $g_0$ aparece en cualquiera de las cuatro columnas GUID:

$$
\mathcal{L}(g_0) = \bigl\{\, e \in \mathcal{E} \;:\;
  g_0 \in \{\,
    e.\text{ProcessGuid},\;
    e.\text{ParentProcessGuid},\;
    e.\text{SourceProcessGUID},\;
    e.\text{TargetProcessGUID}
  \,\}
\bigr\}
$$

Incluir los cuatro k-pairs es necesario porque $g_0$ puede aparecer no solo como
proceso activo (k=1) sino también como proceso que lanzó hijos (k=2), como origen
de una inyección remota (k=3), o como objetivo de un acceso (k=4). Restringir a
k=1 produciría una ventana temporal más estrecha que la real.

Sea entonces:

$$
t_{\min}(g_0) = \min_{e \,\in\, \mathcal{L}(g_0)} t(e)
\qquad
t_{\max}(g_0) = \max_{e \,\in\, \mathcal{L}(g_0)} t(e)
$$

Si el timestamp del evento centinela $t^*$ cumple:

$$
t_{\min}(g_0) \;\leq\; t^* \;\leq\; t_{\max}(g_0)
$$

el centinela cae dentro del ciclo de vida conocido de $g_0$, lo que constituye
evidencia fuerte (aunque no concluyente) de que la asignación es correcta.

Si $t^* > t_{\max}(g_0)$, el evento centinela ocurre **después** del último evento
conocido de $g_0$ — señal de posible reuso de PID — y la acción pasa a `REVIEW`.

La investigación empírica sobre `run-01-apt-1` reveló un tercer caso no contemplado
en la formulación inicial: $t^* < t_{\min}(g_0)$. En el evento 04 (PID 2968,
`endofroad.boombox.local`), $t^*$ ocurre **2 ms antes** de $t_{\min}(g_0)$.
Esto no es reuso de PID sino el artefacto opuesto: Sysmon capturó el evento
antes de tener el GUID del proceso disponible, y 2 ms después comenzó a registrar
eventos con el GUID real. El centinela es un evento "pre-GUID" del mismo proceso.

Introducimos una tolerancia $\delta > 0$ (a calibrar sobre más ejemplos) para
absorber este tipo de artefacto. La regla completa para el caso $\lvert\mathcal{G}\rvert = 1$ es:

$$
\text{acción}(e^*, g_0) =
\begin{cases}
\texttt{REPLACE\_GUID} & \text{si } t_{\min}(g_0) - \delta \;\leq\; t^* \;\leq\; t_{\max}(g_0) \\
\texttt{REVIEW}        & \text{si } t^* < t_{\min}(g_0) - \delta \quad \text{(brecha grande: posible proceso anterior)} \\
\texttt{REVIEW}        & \text{si } t^* > t_{\max}(g_0) \quad \text{(después del ciclo de vida: posible reuso de PID)}
\end{cases}
$$

El valor de $\delta$ es un parámetro empírico. El evento 04 sugiere $\delta \geq 2\,\text{ms}$;
los demás casos del dataset fijarán su cota superior.

---

## Resultados empíricos — `run-01-apt-1`, k=1 (36 eventos)

| $\lvert\mathcal{G}(p,c)\rvert$ | Eventos | Acción preliminar |
|--------------------------------|---------|-------------------|
| $= 1$ | 28 | `REPLACE_GUID` (sujeto a verificación temporal) |
| $> 1$ | 8 | `REVIEW` |
| $= 0$ | 0 | `BOOT_ARTIFACT` |

El Enfoque B (unión de los cuatro k-pairs) encuentra candidato de GUID para los
**36 de 36 eventos** centinela k=1. El Enfoque A (solo k=1) encontraba candidato
para 2 de 36 (6 %). La búsqueda cruzada por k-pairs es esencial.

El análisis caso por caso avanza en el notebook `9_enfoque_B.ipynb`.

---

## Caso de estudio — Evento 04: PID 2968, `endofroad.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV (`_original_row_index`) | 19619 |
| EventID | 7 (ImageLoad) — EID=7 ∉ {8,10}, válido en $\mathcal{E}_1$ |
| Image | `C:\Windows\System32\conhost.exe` |
| `ts` ($t^*$) | 2025-03-19 05:04:05.550 UTC |

**Resultado de $\mathcal{G}(2968,\, \texttt{endofroad})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad \mathcal{G}_3 = \emptyset, \quad \mathcal{G}_4 = \emptyset
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `44d66c27-5045-67da-3600-000000007100`.

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{05:04:05.552} \qquad t^* = \texttt{05:04:05.550} \qquad t_{\max}(g_0) = \texttt{05:04:06.014}
$$

$$
t^* < t_{\min}(g_0) \quad \Rightarrow \quad t^* \notin [t_{\min}(g_0),\, t_{\max}(g_0)]
$$

El evento centinela ocurre **2 ms antes** del primer evento registrado con GUID real.
La figura siguiente muestra esta situación:

```{figure} img/ev04_timeline.png
:name: ev04-timeline
:width: 100%

**Evento 04 — brecha pre-GUID de 2 ms.**
Panel superior: ciclo de vida completo de $g_0$ (30 eventos totales, span = 462 ms).
Por claridad visual solo se aprecian algunos puntos azules — la mayoría de los 30 eventos
están agrupados en los primeros 170 ms y se solapan en el scatter.
La línea verde marca el EID=1 (ProcessCreate), que coincide con $t_{\min}(g_0)$;
la línea naranja marca el EID=5 (ProcessTerminate), que coincide con $t_{\max}(g_0)$.
La línea roja discontinua es el evento centinela $t^*$, 2 ms antes del ProcessCreate.
Panel inferior: zoom sobre la brecha — $t^*$ ocurre antes incluso de que Sysmon
registrara la creación del proceso.
```

**Mecanismo:** el evento centinela es un **ImageLoad (EID=7)** — Sysmon registra
la carga de la propia imagen ejecutable de `conhost.exe` durante la inicialización
del proceso. El driver interceptó este evento antes de completar la asignación del
GUID (que ocurre al procesar el EID=1), de ahí el centinela. 2 ms después el driver
terminó la inicialización y todos los eventos subsiguientes quedaron registrados con $g_0$.

### Hipótesis evaluadas

**H1 — auto-carga durante inicialización (confirmada):**
`dsregcmd.exe` (PID 2668) llama a `CreateProcess()` para lanzar `conhost.exe`
(PID 2968). Durante la fase de inicialización el kernel mapea la imagen ejecutable
en el espacio del nuevo proceso, lo que dispara EID=7 inmediatamente. En ese instante
el driver de Sysmon aún no ha procesado el EID=1 y el GUID no está en su tabla
interna → centinela $\emptyset$. 2 ms después el driver procesa el EID=1, asigna
$g_0$, y todos los eventos subsiguientes ya lo llevan.

**H2 — carga por proceso externo (descartada):**
Otro proceso con GUID centinela propio cargó `conhost.exe` como módulo antes de
que existiera la instancia PID 2968. Requeriría reuso de PID en $\leq 2\,\text{ms}$;
no existe evidencia de ningún proceso candidato en el dataset.

**Evidencia que confirma H1:**

| Evidencia | Valor observado | Interpretación |
|-----------|-----------------|----------------|
| `Image` | `C:\Windows\System32\conhost.exe` | proceso propietario del evento |
| `ImageLoaded` | `C:\Windows\System32\conhost.exe` | imagen cargada = propia imagen del proceso → auto-carga |
| `User` en centinela | `NT AUTHORITY\SYSTEM` | idéntico al `User` del EID=1 de $g_0$ → mismo proceso |
| Eventos previos con PID 2968 y GUID real | ninguno | no hay instancia previa que compita por ese PID |
| `ParentProcessId` en EID=1 | 2668 (`dsregcmd.exe`) | proceso creador identificado sin ambigüedad |

**Nombre de código del escenario:** `PRE_GUID_INIT` — evento capturado por Sysmon
durante la inicialización del proceso, antes de que el driver completara la
asignación del GUID.

No es reuso de PID; es una **condición de carrera entre EID=7 y la asignación
interna del GUID en el driver**. La regla de recuperación con tolerancia $\delta$
absorbe exactamente este tipo de artefacto:

$$
t_{\min}(g_0) - \delta \;\leq\; t^* \quad (\delta = 2\,\text{ms})
\;\implies\; \texttt{REPLACE_GUID} \quad [\texttt{PRE_GUID_INIT}]
$$

La cota inferior observada hasta ahora es $\delta \geq 2\,\text{ms}$.
