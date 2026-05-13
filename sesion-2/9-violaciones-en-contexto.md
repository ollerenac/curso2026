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

---

## Caso de estudio — Grupo eventos 05–23: PID 1972, `diskjockey.boombox.local`

**Datos del grupo:**

| Campo | Valor |
|-------|-------|
| Filas CSV | 22960–22993 (19 eventos) |
| EventID | 7 (ImageLoad) — todos |
| Image | `C:\Windows\System32\taskhostw.exe` |
| `ts` ($t^*$) | 2025-03-19 05:04:29.691 UTC — idéntico en los 19 |

Los 19 eventos centinela comparten `(ProcessId=1972, Computer=diskjockey)`.
Dado que $\mathcal{G}(p,c)$ depende solo de ese par, se calcula una única vez y
aplica a todos.

**Resultado de $\mathcal{G}(1972,\, \texttt{diskjockey})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \emptyset, \quad \mathcal{G}_4 = \emptyset
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `2d5a9c51-505d-67da-2600-000000009000`.

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 45 \text{ eventos}
\quad (k_1 = 37,\; k_2 = 0,\; k_3 = 0,\; k_4 = 8)
$$

Los 8 eventos k=4 son EID=10 (ProcessAccess): procesos del sistema abrieron
handle a `taskhostw.exe` inmediatamente después de su creación — comportamiento
estándar de Windows para auditoría de tokens y escaneo de seguridad.

| `ts` | EID | `SourceProcessId` | `SourceImage` | `SourceProcessGUID` |
|------|-----|-------------------|---------------|---------------------|
| 05:04:29.691 | 10 | 992 | `svchost.exe` | `2d5a9c51-cee0-67da-1100-000000009000` |
| 05:04:29.691 | 10 | 992 | `svchost.exe` | `2d5a9c51-cee0-67da-1100-000000009000` |
| 05:04:29.691 | 10 | 852 | `svchost.exe` | `2d5a9c51-cee0-67da-0e00-000000009000` |
| 05:04:29.691 | 10 | 800 | `svchost.exe` | `2d5a9c51-cee0-67da-0d00-000000009000` |
| 05:04:29.691 | 10 | 376 | `csrss.exe`   | `2d5a9c51-cede-67da-0600-000000009000` |
| 05:04:29.691 | 10 | 992 | `svchost.exe` | `2d5a9c51-cee0-67da-1100-000000009000` |
| 05:04:29.723 | 10 | 600 | `lsass.exe`   | `2d5a9c51-cede-67da-0c00-000000009000` |
| 05:04:29.723 | 10 | 600 | `lsass.exe`   | `2d5a9c51-cede-67da-0c00-000000009000` |

`TargetProcessId = 1972`, `TargetProcessGUID = g_0`, `TargetImage = taskhostw.exe` en todos.

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{05:04:29.691} \qquad t^* = \texttt{05:04:29.691}
\qquad t_{\max}(g_0) = \texttt{05:04:34.280}
$$

$$
t^* = t_{\min}(g_0) \quad \Rightarrow \quad
t_{\min}(g_0) - \delta \;\leq\; t^* \;\leq\; t_{\max}(g_0)
\;\text{ para cualquier } \delta \geq 0
$$

El gap es **0 ms**: el centinela y los primeros eventos con GUID real caen en
el mismo milisegundo. La figura siguiente muestra el ciclo de vida completo y
el zoom sobre la ventana de inicialización:

```{figure} img/ev05_23_timeline.png
:name: ev05-23-timeline
:width: 100%

**Grupo 05–23 — inicialización de `taskhostw.exe` (PID 1972).**
Panel superior: ciclo de vida completo de $g_0$ (45 eventos, span = 4589 ms).
Puntos azules (k=1): proceso activo. Triángulos naranja (k=4): `taskhostw.exe`
como objetivo de ProcessAccess (EID=10) por procesos del sistema.
Línea roja discontinua: los 19 centinelas $t^*$, coincidente con $t_{\min}(g_0)$.
Línea verde: EID=1 ProcessCreate (+1 ms). Línea rojo oscuro: EID=5 ProcessTerminate.
Panel inferior (zoom 0–100 ms): ráfaga de inicialización en $t=0$ ms y segunda
ola de 26 cargas de DLL a $t \approx 32$ ms, una vez asignado $g_0$.
```

**Interpretación — `PRE_GUID_INIT` con gap = 0 ms:**

`svchost.exe` (PID 992) lanza `taskhostw.exe` con la instrucción
`taskhostw.exe SYSTEM`. Durante la inicialización, el loader de Windows
mapea en memoria los módulos estáticos del ejecutable — las 19 DLLs de la
tabla siguiente — antes de que el driver de Sysmon haya procesado el EID=1
y asignado $g_0$. A diferencia del evento 04 (gap = 2 ms), aquí el GUID se
asigna **dentro del mismo milisegundo**: algunos EID=7 de ese batch reciben
$\emptyset$ y otros ya reciben $g_0$.

| DLL cargada pre-GUID (`ImageLoaded`) |
|--------------------------------------|
| `combase.dll`, `imm32.dll`, `sechost.dll`, `clbcatq.dll`, `win32u.dll` |
| `rpcrt4.dll`, `oleaut32.dll`, `ucrtbase.dll`, `dimsjob.dll`, `pautoenr.dll` |
| `msvcrt.dll`, `gdi32full.dll`, `bcryptprimitives.dll`, `netprofm.dll` |
| `KernelBase.dll`, `taskhostw.exe` (auto-carga), `kernel.appcore.dll` |
| `msvcp_win.dll`, `npmproxy.dll` |

El número elevado de DLLs pre-GUID (19 vs 1 en el evento 04) refleja que
`taskhostw.exe` es un **host de tareas COM** con muchas dependencias estáticas,
frente al `conhost.exe` que es un proceso de consola liviano.

**Aplicación de la regla de recuperación:**

$$
t_{\min}(g_0) - \delta \;\leq\; t^* \quad (\delta = 0\,\text{ms})
\;\implies\; \texttt{REPLACE_GUID} \quad [\texttt{PRE_GUID_INIT}]
$$

$g_0$ es el GUID correcto para los 19 eventos centinela.
El caso confirma que $\delta$ puede ser 0 — no se requiere tolerancia
cuando el centinela y el primer evento con GUID real caen en el mismo
milisegundo.

---

## Caso de estudio — Evento 24: PID 3088, `diskjockey.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV | 26579 |
| EventID | 7 (ImageLoad) |
| `Image` | `C:\Windows\System32\cmd.exe` |
| `ImageLoaded` | `C:\Windows\System32\cmd.exe` |
| `ts` ($t^*$) | 2025-03-19 05:04:35.485 UTC |
| `User` | `NT AUTHORITY\SYSTEM` |

**Resultado de $\mathcal{G}(3088,\, \texttt{diskjockey})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \{g_0\}, \quad
\mathcal{G}_3 = \{g_0\}, \quad \mathcal{G}_4 = \{g_0\}
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `2d5a9c51-5063-67da-4e00-000000009000`.

A diferencia de los casos anteriores, **los cuatro k-pairs concurren en $g_0$**:
$\mathcal{G}_2 \neq \emptyset$ porque `cmd.exe` generó un proceso hijo cuyo EID=1
registra `ParentProcessGuid = g_0`; $\mathcal{G}_3$ y $\mathcal{G}_4$ son no vacíos
por eventos EID=10 (ProcessAccess) en los que `cmd.exe` actúa como origen
y como objetivo respectivamente.

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 16 \text{ eventos}
\quad (k_1 = 11,\; k_2 = 1,\; k_3 = 1,\; k_4 = 3)
\quad \text{span} = 18\,\text{ms}
$$

Desglose por k-pair y EventID:

| k-pair | EID | Cantidad | Interpretación |
|--------|-----|----------|----------------|
| k1 | 7 | 9 | DLLs cargadas por `cmd.exe` (con $g_0$ ya asignado) |
| k1 | 1 | 1 | EID=1 ProcessCreate de `cmd.exe` |
| k1 | 5 | 1 | EID=5 ProcessTerminate de `cmd.exe` |
| k2 | 1 | 1 | EID=1 del proceso hijo (`sc.exe`): `ParentProcessGuid = g_0` |
| k3 | 10 | 1 | EID=10: `cmd.exe` (origen) abre handle a otro proceso |
| k4 | 10 | 3 | EID=10: 3 procesos del sistema abren handle a `cmd.exe` |

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{05:04:35.485} \qquad t^* = \texttt{05:04:35.485}
\qquad t_{\max}(g_0) = \texttt{05:04:35.503}
$$

$$
t^* = t_{\min}(g_0) \quad \Rightarrow \quad
t_{\min}(g_0) - \delta \;\leq\; t^* \;\leq\; t_{\max}(g_0)
\;\text{ para cualquier } \delta \geq 0
$$

Gap = **0 ms**: el centinela EID=7 (auto-carga de `cmd.exe`) y el primer evento
con GUID real caen en el mismo milisegundo — patrón `PRE_GUID_INIT` idéntico
al grupo 05–23.

**Proceso creador (EID=1):**

| Campo | Valor |
|-------|-------|
| `ProcessGuid` | `2d5a9c51-5063-67da-4e00-000000009000` ($g_0$) |
| `ParentProcessId` | 1620 |
| `ParentImage` | `C:\Windows\System32\cmd.exe` |
| `ParentProcessGuid` | `2d5a9c51-5053-67da-1d00-000000009000` |
| `CommandLine` | `C:\Windows\system32\cmd.exe /c sc.exe qc npcap` |
| `User` | `NT AUTHORITY\SYSTEM` |

El proceso es un `cmd.exe` lanzado por otro `cmd.exe` (PID 1620) con la
instrucción `/c sc.exe qc npcap` — consulta de la configuración del servicio
`npcap` (driver de captura de red). Ambos tienen GUID real válido:
el padre `ParentProcessGuid` es real y $\mathcal{G}_2 = \{g_0\}$ confirma
que el hijo (`sc.exe`) fue registrado correctamente.

La figura siguiente muestra el ciclo de vida completo y el zoom sobre la
brecha pre-GUID:

```{figure} img/ev24_timeline.png
:name: ev24-timeline
:width: 100%

**Evento 24 — inicialización de `cmd.exe` (PID 3088, `diskjockey`).**
Panel superior: ciclo de vida de $g_0$ (16 eventos, span = 18 ms).
Puntos azules (k1): proceso activo. Cuadrado verde (k2): hijo `sc.exe` (EID=1, +3 ms).
Triángulo morado (k3): `cmd.exe` como origen de ProcessAccess (EID=10).
Triángulos naranja (k4): 3 procesos del sistema accediendo a `cmd.exe` (EID=10).
Línea roja discontinua: centinela $t^*$, coincidente con $t_{\min}(g_0)$.
Línea verde: EID=1 ProcessCreate (+3 ms). Línea rojo oscuro: EID=5 ProcessTerminate.
Panel inferior (zoom): $t^* = t_{\min}(g_0)$ — gap = 0 ms.
```

**Aplicación de la regla de recuperación:**

$$
t_{\min}(g_0) - \delta \;\leq\; t^* \quad (\delta = 0\,\text{ms})
\;\implies\; \texttt{REPLACE_GUID} \quad [\texttt{PRE_GUID_INIT}]
$$

$g_0$ es el GUID correcto para el evento centinela.
El patrón `PRE_GUID_INIT` se confirma por tercera vez: EID=7 auto-carga
(`Image == ImageLoaded`), gap = 0 ms, y los cuatro k-pairs apuntan al
mismo $g_0$.

---

## Caso de estudio — Evento 25: PID 3684, `diskjockey.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV | 26597 |
| EventID | 7 (ImageLoad) |
| `Image` | `C:\Windows\System32\sc.exe` |
| `ImageLoaded` | `C:\Windows\System32\sc.exe` |
| `ts` ($t^*$) | 2025-03-19 05:04:35.501 UTC |

Este evento es el hijo directo del evento 24: el `sc.exe` (PID 3684) identificado
en $\mathcal{G}_2$ de `cmd.exe` (PID 3088). Su `ParentProcessGuid` en el EID=1
es $g_0^{(24)}$, confirmando la cadena de ejecución:

$$
\texttt{cmd.exe}\;(\text{PID 1620})
\;\to\; \texttt{cmd.exe}\;(\text{PID 3088})
\;\to\; \texttt{sc.exe}\;(\text{PID 3684})
\quad [\texttt{sc.exe qc npcap}]
$$

**Resultado de $\mathcal{G}(3684,\, \texttt{diskjockey})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \emptyset, \quad \mathcal{G}_4 = \{g_0\}
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `2d5a9c51-5063-67da-4f00-000000009000`.
`sc.exe` no crea procesos hijos ($\mathcal{G}_2 = \emptyset$) ni accede
a otros procesos ($\mathcal{G}_3 = \emptyset$).

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 11 \text{ eventos}
\quad (k_1 = 8,\; k_4 = 3)
\quad \text{span} = 2\,\text{ms}
$$

| k-pair | EID | Cantidad | Interpretación |
|--------|-----|----------|----------------|
| k1 | 7 | 6 | DLLs cargadas con $g_0$ ya asignado |
| k1 | 1 | 1 | EID=1 ProcessCreate de `sc.exe` |
| k1 | 5 | 1 | EID=5 ProcessTerminate de `sc.exe` |
| k4 | 10 | 3 | Procesos del sistema accediendo a `sc.exe` |

**Nota sobre el orden de eventos:** el EID=5 (ProcessTerminate) tiene timestamp
`05:04:35.501` y el EID=1 (ProcessCreate) tiene `05:04:35.503` — orden inverso
al esperado. Es un artefacto de buffering ETW: `sc.exe qc npcap` completa
su ejecución en menos de 2 ms y los eventos del batch se flushan con timestamps
que no preservan el orden intra-milisegundo exacto.

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{05:04:35.501} \qquad t^* = \texttt{05:04:35.501}
\qquad t_{\max}(g_0) = \texttt{05:04:35.503}
$$

Gap = **0 ms** — mismo patrón `PRE_GUID_INIT` que los casos anteriores.

```{figure} img/ev25_timeline.png
:name: ev25-timeline
:width: 100%

**Evento 25 — inicialización de `sc.exe` (PID 3684, `diskjockey`).**
Panel superior: ciclo de vida de $g_0$ (11 eventos, span = 2 ms).
Puntos azules (k1): proceso activo. Triángulos naranja (k4): 3 procesos
del sistema accediendo a `sc.exe` (EID=10).
Línea roja discontinua: centinela $t^*$, coincidente con $t_{\min}(g_0)$.
Línea verde: EID=1 ProcessCreate (+2 ms). Línea rojo oscuro: EID=5 ProcessTerminate (+0 ms).
Panel inferior: EID=5 precede a EID=1 en 2 ms — artefacto de buffering ETW.
```

**Aplicación de la regla de recuperación:**

$$
t_{\min}(g_0) - \delta \;\leq\; t^* \quad (\delta = 0\,\text{ms})
\;\implies\; \texttt{REPLACE_GUID} \quad [\texttt{PRE_GUID_INIT}]
$$

$g_0$ es el GUID correcto para el evento centinela.

## Caso de estudio — Evento 28: PID 8404, `theblock.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV | 59263 |
| EventID | 7 (ImageLoad) |
| `Image` | `C:\Windows\System32\conhost.exe` |
| `ImageLoaded` | `C:\Windows\System32\conhost.exe` |
| `ts` ($t^*$) | 2025-03-19 05:07:59.894 UTC |

Hijo de `sc.exe` (PID 3104, evento 27, caso REVIEW). `CommandLine`:
`conhost.exe 0xffffffff -ForceV1` — inicialización estándar de consola Windows.

**Resultado de $\mathcal{G}(8404,\, \texttt{theblock})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \{g_0\}, \quad \mathcal{G}_4 = \{g_0\}
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `4a85d404-512f-67da-1501-000000005500`.

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 37 \text{ eventos}
\quad (k_1 = 35,\; k_3 = 1,\; k_4 = 1)
\quad \text{span} = 151\,\text{ms}
$$

| k-pair | EID | Cantidad | Interpretación |
|--------|-----|----------|----------------|
| k1 | 7 | 33 | DLLs cargadas con $g_0$ ya asignado |
| k1 | 1 | 1 | EID=1 ProcessCreate (+8 ms) |
| k1 | 5 | 1 | EID=5 ProcessTerminate (+151 ms) |
| k3 | 10 | 1 | `conhost.exe` abre handle a otro proceso |
| k4 | 10 | 1 | Proceso del sistema accede a `conhost.exe` |

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{05:07:59.894} \qquad t^* = \texttt{05:07:59.894}
\qquad t_{\max}(g_0) = \texttt{05:08:00.045}
$$

Gap = **0 ms**. El EID=1 aparece a +8 ms de $t_{\min}$ — más tardío que en
casos anteriores (0–3 ms), posiblemente por mayor carga del sistema en `theblock`.

```{figure} img/ev28_timeline.png
:name: ev28-timeline
:width: 100%

**Evento 28 — inicialización de `conhost.exe` (PID 8404, `theblock`).**
Panel superior: ciclo de vida de $g_0$ (37 eventos, span = 151 ms).
Puntos azules (k1): proceso activo (33 DLLs + EID=1 + EID=5).
Triángulo morado (k3): `conhost.exe` abre handle a otro proceso.
Triángulo naranja (k4): proceso del sistema accede a `conhost.exe`.
Línea roja discontinua: centinela $t^*$ en $t_{\min}(g_0)$.
Línea verde: EID=1 ProcessCreate (+8 ms). Línea rojo oscuro: EID=5 (+151 ms).
Panel inferior (zoom 0–15 ms): gap = 0 ms, EID=1 a +8 ms.
```

**Aplicación de la regla de recuperación:**

$$
t_{\min}(g_0) - \delta \;\leq\; t^* \quad (\delta = 0\,\text{ms})
\;\implies\; \texttt{REPLACE_GUID} \quad [\texttt{PRE_GUID_INIT}]
$$

$g_0$ es el GUID correcto para el evento centinela.

## Caso de estudio — Evento 30: PID 10964, `waterfalls.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV | 207839 |
| EventID | 3 (NetworkConnect) |
| `Image` | `<unknown process>` |
| `SourcePort` | 62781 |
| `DestinationIp` | 10.1.0.4 |
| `DestinationPort` | 53 (DNS/UDP) |
| `ts` ($t^*$) | 2025-03-19 07:35:12.340 UTC |

**Resultado de $\mathcal{G}(10964,\, \texttt{waterfalls})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \{g_0\}, \quad \mathcal{G}_4 = \emptyset
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `3fc4fefd-584f-67da-9b01-000000004800` (`nslookup.exe`).

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 12 \text{ eventos}
\quad (k_1 = 11,\; k_3 = 1)
\quad \text{span} = 10\,\text{ms}
$$

| k-pair | EID | Cantidad | Interpretación |
|--------|-----|----------|----------------|
| k1 | 1 | 1 | EID=1 ProcessCreate ($t_{\min}$, +0 ms) |
| k1 | 7 | 8 | DLLs cargadas con $g_0$ asignado |
| k1 | 3 | 1 | EID=3 NetworkConnect con $g_0$ (+9 ms) |
| k1 | 5 | 1 | EID=5 ProcessTerminate (+10 ms) |
| k3 | 3 | 1 | EID=3 NetworkConnect del mismo PID vía k3 |

El EID=3 con $g_0$ (fila 207838, SourcePort 62780) y el evento centinela
(fila 207839, SourcePort 62781) representan **dos conexiones UDP separadas**
al mismo servidor DNS: sockets distintos capturados en milisegundos consecutivos.

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{07:35:12.330} \qquad t^* = \texttt{07:35:12.340}
\qquad t_{\max}(g_0) = \texttt{07:35:12.340}
$$

El evento centinela coincide con $t_{\max}(g_0)$ — ocurre simultáneamente con
EID=5 (ProcessTerminate). Esto contrasta con todos los casos anteriores, donde
$t^* \approx t_{\min}(g_0)$.

```{figure} img/ev30_timeline.png
:name: ev30-timeline
:width: 100%

**Evento 30 — POST_GUID_TERMINATE en `nslookup.exe` (PID 10964, `waterfalls`).**
Panel superior: ciclo de vida completo de $g_0$ (span = 10 ms).
Puntos azules (k1): eventos con $g_0$ asignado. Triángulo verde (k3): conexión EID=3 con $g_0$.
Línea roja discontinua: centinela $t^*$ en $t_{\max}(g_0)$, coincidiendo con EID=5.
Panel inferior (zoom 6–11 ms): ventana de la carrera; el driver de red captura
la segunda conexión UDP (SourcePort 62781, $\emptyset$) mientras el proceso se destruye.
```

**Mecanismo: POST_GUID_TERMINATE**

A diferencia de PRE_GUID_INIT (donde $t^* \lesssim t_{\min}(g_0)$), aquí el GUID se
pierde al *final* del ciclo de vida. `nslookup.exe` es el *iniciador* de las
conexiones UDP (IP origen 10.1.0.6 = `waterfalls`): los dos EID=3 son
consecuencia directa del proceso ejecutando sus consultas DNS, no eventos
capturados por azar. El GUID se pierde en el segundo socket porque el contexto
del proceso estaba siendo liberado simultáneamente.

**Robustez de la recuperación:**

$g_0 \in \mathcal{G}(p,c)$ proviene principalmente de $k_1$ (EID=1, EID=7, EID=5).
El primer EID=3 con $g_0$ (fila 207838) es redundante para la recuperación:
incluso sin él, $|\mathcal{G}| = 1$ y el algoritmo asigna $g_0$ al centinela.
La condición $|\mathcal{G}| = 1$ garantiza la recuperación independientemente
de qué k-pairs específicos contribuyen al conjunto.

**Aplicación de la regla de recuperación:**

$$
t_{\min}(g_0) \;\leq\; t^* \;\leq\; t_{\max}(g_0)
\;\implies\; \texttt{REPLACE\_GUID} \quad [\texttt{TERM\_RACE}]
$$

| Mecanismo | Posición de $t^*$ | Contexto del driver |
|-----------|-------------------|---------------------|
| PRE_GUID_INIT | $t^* \lesssim t_{\min}(g_0)$ | Driver carga imagen antes de asignar GUID |
| POST_GUID_TERMINATE | $t^* \approx t_{\max}(g_0)$ | Driver de red registra conexión durante limpieza |

$g_0$ es el GUID correcto para el evento centinela.

## Caso de estudio — Evento 31: PID 10096, `theblock.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV | 285721 |
| EventID | 3 (NetworkConnect) |
| `Image` | `<unknown process>` |
| `SourceIp` | 10.1.0.5 |
| `SourcePort` | 50863 |
| `DestinationIp` | 192.168.0.4 |
| `DestinationPort` | 8888 (C2) |
| `ts` ($t^*$) | 2025-03-19 05:55:55.509 UTC |

**Resultado de $\mathcal{G}(10096,\, \texttt{theblock})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \emptyset, \quad \mathcal{G}_4 = \{g_0\}
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `4a85d404-5c6b-67da-4702-000000005500` (`curl.exe`).

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 21 \text{ eventos}
\quad (k_1 = 18,\; k_4 = 3)
\quad \text{span} = 238\,\text{ms}
$$

| k-pair | EID | Cantidad | Interpretación |
|--------|-----|----------|----------------|
| k1 | 1 | 1 | EID=1 ProcessCreate ($t_{\min}$, +0 ms) |
| k1 | 7 | 16 | DLLs cargadas con $g_0$ asignado |
| k1 | 5 | 1 | EID=5 ProcessTerminate (+238 ms) |
| k4 | 10 | 3 | Accesos al proceso `curl.exe` |

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{05:55:55.594} \qquad t^* = \texttt{05:55:55.509}
\qquad t_{\max}(g_0) = \texttt{05:55:55.832}
$$

Gap = **-85 ms** — el mayor observado hasta ahora. `curl.exe` establece la
conexión TCP hacia el C2 antes de que Sysmon complete la asignación del GUID,
adelantándose 85 ms a $t_{\min}(g_0)$.

```{figure} img/ev31_timeline.png
:name: ev31-timeline
:width: 100%

**Evento 31 — PRE_GUID_INIT en `curl.exe` (PID 10096, `theblock`).**
Panel superior: ciclo de vida de $g_0$ (21 eventos, span = 238 ms).
Puntos azules (k1): proceso activo. Triángulos naranja (k4): accesos EID=10.
Línea roja discontinua: centinela $t^*$ a -85 ms. Línea verde: EID=1 ($t_{\min}$). Línea rojo oscuro: EID=5.
Panel inferior (zoom -90 a +15 ms): brecha PRE_GUID_INIT de 85 ms.
```

**Contexto APT:** la `CommandLine` del EID=1 revela tráfico C2:

```
curl -s -H "KEY:ADMIN123" -H "Content-Type: application/json"
     -X PATCH http://192.168.0.4:8888/api/v2/agents/muoevz -d '{"watchdog":1}'
```

El agente malicioso actualiza su estado en el servidor de control.
No existe ningún EID=3 con $g_0$ real — la recuperación proviene exclusivamente
de $k_1$ (EID=1, EID=7, EID=5), confirmando la robustez de la condición $|\mathcal{G}|=1$.

**Aplicación de la regla de recuperación:**

$$
t^* < t_{\min}(g_0) \quad (\delta = -85\,\text{ms})
\;\implies\; \texttt{REPLACE\_GUID} \quad [\texttt{PRE\_GUID\_INIT}]
$$

$g_0$ es el GUID correcto para el evento centinela.

## Casos de estudio — Eventos 32 y 33: PID 15048, `waterfalls.boombox.local`

**Datos de los eventos centinela $e^*$:**

| Campo | Evento 32 | Evento 33 |
|-------|-----------|-----------|
| Fila CSV | 290446 | 290447 |
| EventID | 3 (NetworkConnect) | 3 (NetworkConnect) |
| `Image` | `<unknown process>` | `<unknown process>` |
| `SourcePort` | 63514 | 63515 |
| `DestinationIp` | 10.1.0.4 | 10.1.0.4 |
| `DestinationPort` | 53 (DNS/UDP) | 53 (DNS/UDP) |
| `ts` ($t^*$) | 2025-03-19 05:58:23.372 UTC | 2025-03-19 05:58:23.373 UTC |

Ambos centinelas pertenecen al mismo proceso: `nslookup.exe` (PID 15048),
hijo de `MSExchangeHMWorker.exe`, ejecutando
`nslookup.exe -type=A WATERFALLS.boombox.local. 10.1.0.4`.

**Resultado de $\mathcal{G}(15048,\, \texttt{waterfalls})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \emptyset, \quad \mathcal{G}_4 = \{g_0\}
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `3fc4fefd-5cff-67da-fa01-000000004800`.

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 16 \text{ eventos}
\quad (k_1 = 13,\; k_4 = 3)
\quad \text{span} = 13\,\text{ms}
$$

**Verificación temporal:**

$$
t^*_{[0]} = \texttt{05:58:23.372}, \quad t^*_{[1]} = \texttt{05:58:23.373}
\qquad t_{\min}(g_0) = \texttt{05:58:23.403}
$$

$$
t^* < t_{\min}(g_0) \quad (\delta = -31\,\text{ms})
$$

Ambas conexiones DNS se abren dentro de una ventana de 1 ms entre sí,
31 ms antes de que Sysmon asigne el ProcessGuid.

```{figure} img/ev32_timeline.png
:name: ev32-timeline
:width: 100%

**Eventos 32/33 — PRE_GUID_INIT en `nslookup.exe` (PID 15048, `waterfalls`).**
Panel superior: ciclo de vida de $g_0$ (16 eventos, span = 13 ms).
Dos líneas rojas discontinuas: los dos centinelas a -31 ms y -30 ms.
Panel inferior (zoom): brecha PRE_GUID_INIT de 31 ms con los dos sockets DNS.
```

**Contraste con Evento 30** (misma imagen, mismo host):

| | Evento 30 (PID 10964) | Eventos 32/33 (PID 15048) |
|--|----------------------|---------------------------|
| EID=3 con $g_0$ | 1 (SourcePort 62780) | 0 |
| EID=3 centinelas | 1 (SourcePort 62781) | 2 (puertos 63514, 63515) |
| Mecanismo | POST_GUID_TERMINATE | PRE_GUID_INIT |
| Posición de $t^*$ | $t_{\max}(g_0)$ | $t_{\min}(g_0) - 31\,\text{ms}$ |

La misma imagen (`nslookup.exe`) en el mismo host puede producir ambos
mecanismos dependiendo del momento en que el driver de red captura las
conexiones relativo al ciclo de vida del GUID.

**Aplicación de la regla de recuperación:**

$$
t^* < t_{\min}(g_0) \quad (\delta = -31\,\text{ms})
\;\implies\; \texttt{REPLACE\_GUID} \quad [\texttt{PRE\_GUID\_INIT}]
$$

$g_0$ es el GUID correcto para ambos eventos centinela.

## Caso de estudio — Evento 34: PID 4020, `diskjockey.boombox.local`

**Datos del evento centinela $e^*$:**

| Campo | Valor |
|-------|-------|
| Fila CSV | 305809 |
| EventID | 7 (ImageLoad) |
| `Image` | `C:\Windows\System32\wsqmcons.exe` |
| `ImageLoaded` | `C:\Windows\System32\ktmw32.dll` |
| `ts` ($t^*$) | 2025-03-19 06:00:01.816 UTC |

**Resultado de $\mathcal{G}(4020,\, \texttt{diskjockey})$:**

$$
\mathcal{G}_1 = \{g_0\}, \quad \mathcal{G}_2 = \emptyset, \quad
\mathcal{G}_3 = \emptyset, \quad \mathcal{G}_4 = \{g_0\}
\quad \Rightarrow \quad \lvert\mathcal{G}\rvert = 1
$$

donde $g_0 =$ `2d5a9c51-5d61-67da-7600-000000009000` (`wsqmcons.exe`).

**Ciclo de vida $\mathcal{L}(g_0)$:**

$$
\lvert\mathcal{L}(g_0)\rvert = 15 \text{ eventos}
\quad (k_1 = 13,\; k_4 = 2)
\quad \text{span} = 2\,\text{ms}
$$

| k-pair | EID | Cantidad | Interpretación |
|--------|-----|----------|----------------|
| k1 | 7 | 11 | DLLs cargadas (incluyendo centinela en $t_{\min}$) |
| k1 | 5 | 1 | EID=5 ProcessTerminate (en $t_{\min}$, artefacto ETW) |
| k1 | 1 | 1 | EID=1 ProcessCreate (+2 ms, artefacto ETW) |
| k4 | 10 | 2 | Accesos externos al proceso |

**Verificación temporal:**

$$
t_{\min}(g_0) = \texttt{06:00:01.816} \qquad t^* = \texttt{06:00:01.816}
\qquad t_{\max}(g_0) = \texttt{06:00:01.818}
$$

Gap = **0 ms**. El EID=1 aparece a +2 ms — mismo artefacto ETW que en
Evento 25 (`sc.exe`): proceso creado y terminado casi instantáneamente,
con EID=1 y EID=5 bufferizados en orden inverso al real.

```{figure} img/ev34_timeline.png
:name: ev34-timeline
:width: 100%

**Evento 34 — PRE_GUID_INIT en `wsqmcons.exe` (PID 4020, `diskjockey`).**
Panel superior: ciclo de vida de $g_0$ (15 eventos, span = 2 ms).
Puntos azules (k1): proceso activo. Triángulos naranja (k4): accesos EID=10.
Línea roja discontinua: centinela $t^*$ en $t_{\min}(g_0)$ (gap = 0 ms).
Línea verde: EID=1 a +2 ms. Línea rojo oscuro: EID=5 en $t_{\min}$ (artefacto ETW).
Panel inferior (zoom): brecha gap = 0 ms, EID=1 visible a +2 ms.
```

**Aplicación de la regla de recuperación:**

$$
t^* \approx t_{\min}(g_0) \quad (\delta = 0\,\text{ms})
\;\implies\; \texttt{REPLACE\_GUID} \quad [\texttt{PRE\_GUID\_INIT}]
$$

**Este es el último caso REPLACE_GUID con $|\mathcal{G}|=1$.**
Todos los casos analizados confirman PRE_GUID_INIT como el mecanismo
dominante de pérdida de GUID en EID=7 (ImageLoad).

$g_0$ es el GUID correcto para el evento centinela.

---

## Casos REVIEW — Eventos 0–3: PID 3364, `endofroad.boombox.local`

**Datos de partida:** 4 eventos EID=3 con `ProcessGuid = ∅`, `ProcessId = 3364`,
`Computer = endofroad.boombox.local`. `compute_G(3364, endofroad)` devuelve
$|\mathcal{G}| = 2$ → caso `REVIEW`.

### Desambiguación por proximidad temporal

Cuando $|\mathcal{G}| > 1$, la invariante de unicidad falla por **reuso de PID**:
el sistema operativo reutilizó el mismo número de proceso para un proceso distinto
después de que el primero terminara. Calculamos el delta temporal entre cada
centinela $t^*$ y el $t_{\min}$ de cada GUID candidato:

| GUID | Proceso (`Image`) | $t_{\min}$ | $\Delta(t^* - t_{\min})$ | Veredicto |
|------|-------------------|-----------|--------------------------|-----------|
| gA | `dsregcmd.exe` | 05:01:15 | **−55 ms** | PRE_GUID_INIT ← correcto |
| gB | `conhost.exe`  | 05:04:11 | −176 s     | Reuso de PID posterior    |

La escala temporal es el criterio decisivo: **55 ms** (milisegundos, PRE_GUID_INIT)
frente a **176 segundos** (casi 3 minutos, reuso claro). No hay ambigüedad.

```{figure} img/ev03_timeline.png
:name: ev03-timeline
:width: 100%

**Eventos 0–3 — PRE_GUID_INIT en `dsregcmd.exe` (PID 3364, `endofroad`) con resolución por $|\mathcal{G}|=2$.**
Panel superior: esquema macro (segundos). Los 4 centinelas (líneas discontinuas rojas) se
agrupan en $t \approx 0$. gA (`dsregcmd.exe`, diamante azul) aparece a +55 ms — escala de
milisegundos. gB (`conhost.exe`, diamante naranja) aparece a +176 s — escala de minutos.
La separación visual hace inequívoca la asignación.
Panel inferior: zoom PRE_GUID_INIT en milisegundos. Los 4 centinelas caen entre
−55 ms y −43 ms respecto a $t_{\min}(g_A)$, con EID=7 (steelblue) y EID=1 (verde)
marcando el arranque del proceso.
```

### Destino de los centinelas

Los 4 EID=3 corresponden a conexiones de `dsregcmd.exe` hacia:

| Destino IP | Puerto | Protocolo |
|-----------|--------|-----------|
| 10.1.0.4  | 135    | RPC endpoint mapper |
| 10.1.0.4  | 49667  | RPC dinámico |
| 10.1.0.4  | 389    | LDAP (×2) |

Este patrón es el comportamiento **esperado** de `dsregcmd.exe` al registrar
el equipo en Azure AD / unión al dominio: consulta LDAP y RPC al DC.
No hay indicador de actividad maliciosa en este proceso.

**Aplicación de la regla de recuperación:**

$$
\Delta(t^*, g_A) \approx 55\,\text{ms} \ll \Delta(t^*, g_B) \approx 176\,\text{s}
\;\implies\; \texttt{REPLACE\_GUID} \leftarrow g_A \quad [\texttt{PRE\_GUID\_INIT}]
$$

---

## Caso de estudio — Evento 26: PID 5096, `theblock.boombox.local`

**Datos de partida:** 1 evento EID=7 con `ProcessGuid = ∅`, `ProcessId = 5096`,
`Computer = theblock.boombox.local`, `Image = conhost.exe`, `ImageLoaded = ucrtbase.dll`.
`compute_G(5096, theblock)` devuelve $|\mathcal{G}| = 3$ → caso `REVIEW`.

### Reuso de PID pasado, presente y futuro

Este es el primer caso con **tres procesos distintos** asignados al mismo PID, incluyendo
reuso tanto en el pasado como en el futuro respecto al centinela:

| GUID | Proceso | $t_{\min}$ | $\Delta(t^* - t_{\min})$ | Veredicto |
|------|---------|-----------|--------------------------|-----------|
| gA | `<sin EID=1>` (solo EID=5) | 05:03:58 | +65 s | PID reuse **pasado** — ya terminado |
| gB | `conhost.exe` (EID=7) | 05:05:03.082 | **−16 ms** | **PRE_GUID_INIT** ← correcto |
| gC | `powershell.exe` | 05:07:35 | −153 s | PID reuse **futuro** — aún no arranca |

**Criterio de selección:** mínimo $|\Delta|$. Con $|\Delta(g_B)| = 16\,\text{ms}$ frente a
$65\,000\,\text{ms}$ (gA) y $152\,835\,\text{ms}$ (gC), gB es el único candidato
consistente con un gap de milisegundos.

```{figure} img/ev26_timeline.png
:name: ev26-timeline
:width: 100%

**Evento 26 — PRE_GUID_INIT en `conhost.exe` (PID 5096, `theblock`) con |G|=3.**
Panel superior: gA (×, gris) terminó 65 s antes del centinela; gB (◆, azul) aparece
16 ms después — escala de milisegundos; gC (◆, naranja, `powershell.exe`) arranca
153 s después — reuso futuro. La escala temporal separa los tres casos.
Panel inferior: zoom PRE_GUID_INIT. El centinela carga `ucrtbase.dll` (sin GUID),
16 ms después gB carga `bcrypt.dll` (con GUID real) en el mismo proceso.
```

**Aplicación de la regla de recuperación:**

$$
|\Delta(t^*, g_B)| = 16\,\text{ms} \ll |\Delta(t^*, g_A)| = 65\,\text{s},\;
|\Delta(t^*, g_C)| = 153\,\text{s}
\;\implies\; \texttt{REPLACE\_GUID} \leftarrow g_B \quad [\texttt{PRE\_GUID\_INIT}]
$$

---

## Caso de estudio — Evento 27: PID 3104, `theblock.boombox.local`

**Datos de partida:** 1 evento EID=7 con `ProcessGuid = ∅`, `ProcessId = 3104`,
`Computer = theblock.boombox.local`, `Image = sc.exe`, `ts = 05:07:59.894`.
`compute_G(3104, theblock)` devuelve $|\mathcal{G}| = 2$ → caso `REVIEW`.

### PRE_GUID_INIT con gap = 0 ms y reuso futuro

| GUID | Proceso | $t_{\min}$ | $\Delta(t^* - t_{\min})$ | Veredicto |
|------|---------|-----------|--------------------------|-----------|
| gA | `sc.exe` (EID=1 ✓) | 05:07:59.894 | **0 ms** | **PRE_GUID_INIT** ← correcto |
| gB | `<sin EID=1>` | 06:06:55 | −3536 s (−59 min) | PID reuse futuro |

El centinela ocurre en el **mismo milisegundo** que $t_{\min}(g_A)$: mismo mecanismo
de batching ETW que el Evento 34. La diferencia de escala — 0 ms vs 59 minutos —
hace la selección trivial. La Image de gA está confirmada por EID=1: `sc.exe`.

```{figure} img/ev27_timeline.png
:name: ev27-timeline
:width: 100%

**Evento 27 — PRE_GUID_INIT en `sc.exe` (PID 3104, `theblock`) con |G|=2.**
Panel superior: gA (◆ azul) solapado con el centinela en $t\approx 0$; gB (◆ naranja)
aparece 59 minutos después — reuso futuro. La escala de minutos separa los dos candidatos.
Panel inferior: ciclo de vida completo de `sc.exe` (span=148 ms). El centinela y
$t_{\min}(g_A)$ coinciden en $x=0$; EID=1 (verde) aparece a +5 ms, EID=5 (rojo) al final.
```

**Aplicación de la regla de recuperación:**

$$
|\Delta(t^*, g_A)| = 0\,\text{ms} \ll |\Delta(t^*, g_B)| = 3\,536\,000\,\text{ms}
\;\implies\; \texttt{REPLACE\_GUID} \leftarrow g_A \quad [\texttt{PRE\_GUID\_INIT}]
$$

---

## Caso de estudio — Evento 29: PID 5548, `theblock.boombox.local`

**Datos de partida:** 1 evento EID=13 (RegistryEvent SetValue) con `ProcessGuid = ∅`,
`ProcessId = 5548`, `Computer = theblock.boombox.local`, `Image = backgroundTaskHost.exe`,
`ts = 05:37:00.686`. `compute_G(5548, theblock)` devuelve $|\mathcal{G}| = 2$ → caso `REVIEW`.

### POST_GUID_TERMINATE con EID=13 (registry write)

Segunda aparición del mecanismo POST_GUID_TERMINATE (cf. Evento 30, EID=3).
El proceso terminó con EID=5 a las 05:37:00.674; el driver de registro capturó
un SetValue **12 ms después**, cuando el contexto del proceso ya estaba siendo liberado.

| GUID | Proceso | $t_{\min}$ / $t_{\max}$ | $\Delta(t^* - t_{\max})$ | Veredicto |
|------|---------|--------------------------|--------------------------|-----------|
| gOld | `<sin EID=1>` | 05:03:16 / 05:03:16 | +2024 s | PID reuse pasado |
| gCorrect | `backgroundTaskHost.exe` | 05:35:54 / **05:37:00.674** | **+12 ms** | **POST_GUID_TERMINATE** ← correcto |

```{figure} img/ev29_timeline.png
:name: ev29-timeline
:width: 100%

**Evento 29 — POST_GUID_TERMINATE en `backgroundTaskHost.exe` (PID 5548, `theblock`) con |G|=2.**
Panel superior: barra azul = ciclo de vida de 66 s; línea punteada roja = EID=5 (terminate);
línea discontinua roja = centinela $t^*$ a +12 ms; gOld (×) a −34 min.
Panel inferior: zoom POST_GUID_TERMINATE. EID=5 en $x=0$, EID=13 centinela a +12 ms.
```

**Aplicación de la regla de recuperación:**

$$
\Delta(t^*, t_{\max}(g_{\mathrm{correct}})) = +12\,\text{ms}
\;\implies\; \texttt{REPLACE\_GUID} \leftarrow g_{\mathrm{correct}} \quad
[\texttt{POST\_GUID\_TERMINATE}]
$$

---
