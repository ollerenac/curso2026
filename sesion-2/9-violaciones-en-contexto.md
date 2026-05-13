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

---
