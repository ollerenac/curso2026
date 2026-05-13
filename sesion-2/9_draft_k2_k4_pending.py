# BORRADOR: celdas k=2, k=4 y ejercicios A/B extraídas de 9_violaciones_en_contexto.ipynb
# Para reintegrar: copiar cada bloque al notebook cuando se retome el análisis de k=2 y k=4.
#

# ── celda original 14 [markdown] ─────────────────────────────
# ---
# ## Invariante 1 en k=2: `ParentProcessGuid` / `ParentProcessId`
# 
# Dominio: eventos con EID = 1 (ProcessCreate).
# El centinela aquí aparece como **padre** — son procesos lanzados durante el boot
# cuyo padre Sysmon no pudo atribuir a ningún GUID real.

# ── celda original 15 [code] ─────────────────────────────
sentinel_k2 = (
    viol[
        (viol['EventID'] == 1) &
        (viol['ParentProcessGuid'] == NULL_GUID)
    ]
    .sort_values('_original_row_index')
    .reset_index(drop=True)
)

print(f'Eventos centinela k=2      : {len(sentinel_k2)}')
print(f'PIDs hijo distintos (Image): {sentinel_k2["Image"].nunique()}')
print(f'PIDs padre distintos       : {sentinel_k2["ParentProcessId"].nunique()}')
print(f'Computers distintos        : {sentinel_k2["Computer"].nunique()}')
print(f'Rango temporal             : {sentinel_k2["ts"].min()} → {sentinel_k2["ts"].max()}')
print(f'\nTop 10 Images (procesos hijo lanzados desde centinela):')
print(sentinel_k2['Image'].value_counts().head(10))

# ── celda original 16 [code] ─────────────────────────────
# Ventana de contexto del primer evento centinela en k=2
first_k2 = sentinel_k2.iloc[0]
idx_k2   = int(first_k2['_original_row_index'])

window_k2 = df.iloc[max(0, idx_k2 - WINDOW) : idx_k2 + WINDOW + 1].copy()
window_k2['▶'] = ''
window_k2.loc[idx_k2, '▶'] = '◀ centinela k=2'

cols_w = ['▶', 'ts', 'EventID', 'ProcessGuid', 'ProcessId',
          'ParentProcessGuid', 'ParentProcessId', 'Image', 'Computer']
window_k2[cols_w].reset_index(drop=True)

# ── celda original 17 [markdown] ─────────────────────────────
# ---
# ## Invariante 1 en k=4: `TargetProcessGUID` / `TargetProcessId`
# 
# Dominio: eventos con EID ∈ {8, 10} (CreateRemoteThread / ProcessAccess).
# El centinela aparece como **proceso objetivo** de una inyección o acceso remoto.

# ── celda original 18 [code] ─────────────────────────────
sentinel_k4 = (
    viol[
        viol['EventID'].isin([8, 10]) &
        (viol['TargetProcessGUID'] == NULL_GUID)
    ]
    .sort_values('_original_row_index')
    .reset_index(drop=True)
)

print(f'Eventos centinela k=4      : {len(sentinel_k4)}')
print(f'TargetProcessIds distintos : {sentinel_k4["TargetProcessId"].nunique()}')
print(f'Computers distintos        : {sentinel_k4["Computer"].nunique()}')
print(f'\nDetalle:')
cols_k4 = ['ts', 'EventID', 'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'Computer']
display(sentinel_k4[cols_k4])

# ── celda original 19 [code] ─────────────────────────────
# Ventana de contexto del primer evento centinela en k=4
first_k4 = sentinel_k4.iloc[0]
idx_k4   = int(first_k4['_original_row_index'])

window_k4 = df.iloc[max(0, idx_k4 - WINDOW) : idx_k4 + WINDOW + 1].copy()
window_k4['▶'] = ''
window_k4.loc[idx_k4, '▶'] = '◀ centinela k=4'

cols_w = ['▶', 'ts', 'EventID', 'ProcessGuid', 'ProcessId',
          'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'Computer']
window_k4[[c for c in cols_w if c in window_k4.columns]].reset_index(drop=True)

# ── celda original 30 [markdown] ─────────────────────────────
# ---
# ## Actividad Práctica
# 
# ### Ejercicio A — Recuperación de GUID para k=2
# 
# El centinela en k=2 aparece como `ParentProcessGuid` en 500 eventos EID=1.
# El GUID correcto del **padre** debería estar en otros eventos de ese padre
# (por ejemplo, el propio EID=1 del padre, o cualquier evento EID ∉ {8,10}
# con mismo `Computer` + `ParentProcessId` que tenga GUID real en `ProcessGuid`).
# 
# Implementa la estrategia de recuperación para k=2 y responde:
# - ¿Qué fracción de los 500 eventos tiene un `ParentProcessGuid` recuperable?
# - ¿Qué `ParentProcessId` valores son irrecuperables? ¿Cuál es su Image típica?

# ── celda original 31 [code] ─────────────────────────────
# --- Ejercicio A ---
# Tabla de búsqueda: eventos con GUID real en ProcessGuid (EID ∉ {8,10})
# que puedan servir como referencia del proceso padre
real_guids = (
    df[
        ~df['EventID'].isin([8, 10]) &
        (df['ProcessGuid'] != NULL_GUID) &
        df['ProcessGuid'].notna()
    ]
    [['Computer', 'ProcessId', 'ProcessGuid', 'Image', 'ts']]
    .copy()
)

print(f'Eventos con GUID real disponibles para búsqueda: {len(real_guids):,}')

# TODO: para cada evento en sentinel_k2, buscar en real_guids por
#       Computer == sentinel_k2['Computer'] y
#       ProcessId == sentinel_k2['ParentProcessId'] y
#       ts <= sentinel_k2['ts']
# TODO: calcular tasa de recuperación
# TODO: listar ParentProcessId irrecuperables con su Image

# ── celda original 32 [markdown] ─────────────────────────────
# ### Ejercicio B — Estrategia de recuperación para k=4
# 
# Para los 2 eventos sentinela de k=4 (`TargetProcessGUID = ∅`),
# busca el GUID correcto del proceso objetivo usando la misma estrategia
# que en k=1 (EID=1 con mismo `Computer` + `TargetProcessId`).
# 
# - ¿Se pueden recuperar? ¿Qué proceso era el objetivo?
# - ¿Qué tipo de evento (EID=8 o EID=10) los genera?
# - ¿Qué proceso SOURCE realizó la operación sobre ese objetivo?

# ── celda original 33 [code] ─────────────────────────────
# --- Ejercicio B ---
print('Detalle de los eventos centinela k=4:')
cols_b = ['ts', 'EventID', 'Computer', 'ProcessGuid', 'ProcessId', 'Image',
          'TargetProcessGUID', 'TargetProcessId', 'TargetImage']
display(sentinel_k4[[c for c in cols_b if c in sentinel_k4.columns]])

# TODO: buscar EID=1 con Computer == sentinel_k4['Computer']
#       y ProcessId == sentinel_k4['TargetProcessId']
#       y ts <= sentinel_k4['ts']
# TODO: mostrar el GUID candidato y validar contra TargetImage
