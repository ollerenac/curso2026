#!/usr/bin/env python3
"""
Extraer eventos Sysmon que corresponden a violaciones de ProcessGuid.

Lee AMBOS archivos de violaciones del directorio del run:
- 04_processguid-pid-violations-run-XX.csv  (violaciones ProcessGuid → PID)
- 04_processguid-image-violations-run-XX.csv (violaciones ProcessGuid → Image)

Para cada par k presente en el CSV de violaciones PID, usa la columna pid_col
original como clave de join (no siempre ProcessId):
  k=1  → join sobre (Computer, ProcessId)
  k=2  → join sobre (Computer, ParentProcessId)
  k=3  → join sobre (Computer, SourceProcessId)
  k=4  → join sobre (Computer, TargetProcessId)

Esto garantiza que los eventos EID=1 (k=2) y EID∈{8,10} (k=3, k=4) que
causaron la violación queden incluidos en la extracción.

El subconjunto se guarda como 04_sysmon-run-XX-violations.csv.

Copia de trabajo de fullapt2025/scripts/pipeline/quality/extract_violation_events.py
adaptada para ejecutarse desde curso2026/sesion-2/quality/.

Uso:
    python extract_violation_events.py --run 1
"""

import pandas as pd
from pathlib import Path
import argparse
import sys
import hashlib
import re

# Ruta al dataset — relativa a sesion-2/quality/
_SCRIPT_DIR = Path(__file__).resolve().parent
DATASET_DIR = _SCRIPT_DIR.parent.parent / "dataset"


def discover_run_dir(run_number):
    pattern = re.compile(r'^run-(\d+)-(apt-\d+)$')
    for item in sorted(DATASET_DIR.iterdir()):
        if item.is_dir():
            match = pattern.match(item.name)
            if match and int(match.group(1)) == run_number:
                return item
    return None


def _build_merge_specs_from_pid(df_pid):
    """
    Construye especificaciones de merge a partir del CSV de violaciones PID.

    Si el CSV tiene columna k_pair (formato nuevo): usa pid_col de cada par k
    como columna de join — así se capturan los eventos que causaron la violación.

    Si no tiene k_pair (formato legacy k=1): join sobre ProcessId.

    Retorna lista de (col_name, keys_df).
    """
    specs = []
    if 'k_pair' in df_pid.columns:
        for k_pair in sorted(df_pid['k_pair'].unique()):
            group        = df_pid[df_pid['k_pair'] == k_pair]
            pid_col_orig = group['pid_col'].iloc[0]
            keys = (group[['Computer', 'ProcessId']]
                    .rename(columns={'ProcessId': pid_col_orig})
                    .drop_duplicates())
            specs.append((pid_col_orig, keys))
            print(f"  k={k_pair}  join sobre (Computer, {pid_col_orig}): {len(keys):,} claves únicas")
    else:
        keys = df_pid[['Computer', 'ProcessId']].drop_duplicates()
        specs.append(('ProcessId', keys))
        print(f"  (formato legacy k=1) join sobre (Computer, ProcessId): {len(keys):,} claves únicas")
    return specs


def extract_violation_events(run_number):
    run_dir = discover_run_dir(run_number)
    if run_dir is None:
        return False, f"Directorio del run no encontrado para run-{run_number:02d}", {}

    pid_violation_file   = run_dir / f"04_processguid-pid-violations-run-{run_number:02d}.csv"
    image_violation_file = run_dir / f"04_processguid-image-violations-run-{run_number:02d}.csv"
    sysmon_file          = run_dir / f"02_sysmon-run-{run_number:02d}.csv"
    output_file          = run_dir / f"04_sysmon-run-{run_number:02d}-violations.csv"

    if not sysmon_file.exists():
        return False, f"Archivo Sysmon no encontrado: {sysmon_file}", {}

    # merge_specs: lista de (col_name, keys_df)
    # Cada entrada indica sobre qué columna del sysmon CSV hacer el join
    merge_specs = []

    if pid_violation_file.exists():
        print(f"Cargando violaciones PID: {pid_violation_file}")
        try:
            df_pid = pd.read_csv(pid_violation_file)
            print(f"  Encontradas {len(df_pid):,} filas de violaciones PID")
            specs = _build_merge_specs_from_pid(df_pid)
            merge_specs.extend(specs)
        except Exception as e:
            print(f"  Advertencia: error cargando violaciones PID: {e}")
    else:
        print(f"Archivo de violaciones PID no encontrado (saltando): {pid_violation_file}")

    if image_violation_file.exists():
        print(f"\nCargando violaciones Image: {image_violation_file}")
        try:
            df_img = pd.read_csv(image_violation_file)
            print(f"  Encontradas {len(df_img):,} filas de violaciones Image")
            keys = df_img[['Computer', 'ProcessId']].drop_duplicates()
            merge_specs.append(('ProcessId', keys))
            print(f"  join sobre (Computer, ProcessId): {len(keys):,} claves únicas")
        except Exception as e:
            print(f"  Advertencia: error cargando violaciones Image: {e}")
    else:
        print(f"Archivo de violaciones Image no encontrado (saltando): {image_violation_file}")

    if not merge_specs:
        return False, f"No se encontraron archivos de violaciones para run-{run_number:02d}", {}

    # Consolidar: si dos fuentes usan la misma columna, unir sus claves
    consolidated = {}
    for col_name, keys in merge_specs:
        if col_name in consolidated:
            consolidated[col_name] = pd.concat([consolidated[col_name], keys]).drop_duplicates()
        else:
            consolidated[col_name] = keys

    merge_specs_final = list(consolidated.items())
    print(f"\nMerge final: {len(merge_specs_final)} columna(s) de join: "
          f"{[col for col, _ in merge_specs_final]}")

    print(f"\nCargando archivo Sysmon: {sysmon_file}")
    print("  (Procesando en chunks para archivos grandes...)")

    try:
        chunk_size = 100_000
        matched_chunks = []
        total_sysmon_events = 0
        chunk_num = 0

        for chunk in pd.read_csv(sysmon_file, chunksize=chunk_size, low_memory=False):
            chunk_num += 1
            chunk_len = len(chunk)
            total_sysmon_events += chunk_len

            chunk['_original_row_index'] = range(
                total_sysmon_events - chunk_len,
                total_sysmon_events
            )

            # Recolectar índices de filas coincidentes (deduplicados por índice)
            matched_indices = set()
            for col_name, keys in merge_specs_final:
                if col_name not in chunk.columns:
                    continue
                sub = chunk.merge(keys, on=['Computer', col_name], how='inner')
                matched_indices.update(sub['_original_row_index'].tolist())

            if matched_indices:
                matched_chunks.append(
                    chunk[chunk['_original_row_index'].isin(matched_indices)].copy()
                )

            if chunk_num % 10 == 0:
                print(f"    Procesados {total_sysmon_events:,} eventos...", end='\r')

        print(f"    Procesados {total_sysmon_events:,} eventos (completo)")

        if matched_chunks:
            df_matched = pd.concat(matched_chunks, ignore_index=True)
        else:
            df_matched = pd.DataFrame()

        matched_count = len(df_matched)
        matched_pct   = (matched_count / total_sysmon_events * 100) if total_sysmon_events > 0 else 0

        print(f"\n  Coincidencias: {matched_count:,} eventos ({matched_pct:.2f}% del total)")

        if matched_count == 0:
            return False, "No se encontraron eventos coincidentes en los datos Sysmon", {}

    except Exception as e:
        return False, f"Error procesando el archivo Sysmon: {e}", {}

    print("  Añadiendo columnas de tracking...")

    def compute_row_hash(row):
        cols_to_hash = sorted([col for col in row.index if not col.startswith('_')])
        hash_input = '_'.join([str(row.get(col, '')) for col in cols_to_hash])
        return 'h' + hashlib.md5(hash_input.encode()).hexdigest()[:8]

    df_matched['_row_hash'] = df_matched.apply(compute_row_hash, axis=1)

    tracking_cols = ['_original_row_index', '_row_hash']
    data_cols = [c for c in df_matched.columns if c not in tracking_cols]
    df_matched = df_matched[tracking_cols + data_cols]

    print(f"  Columnas añadidas: _original_row_index, _row_hash")

    print(f"\nGuardando eventos coincidentes en: {output_file}")
    try:
        df_matched['_row_hash'] = df_matched['_row_hash'].astype(str)
        df_matched.to_csv(output_file, index=False)
    except Exception as e:
        return False, f"Error guardando el archivo de salida: {e}", {}

    unique_violation_processguids = set()
    if pid_violation_file.exists():
        try:
            df_pid2 = pd.read_csv(pid_violation_file)
            unique_violation_processguids.update(df_pid2['ProcessGuid'].unique())
        except Exception:
            pass
    if image_violation_file.exists():
        try:
            df_img2 = pd.read_csv(image_violation_file)
            unique_violation_processguids.update(df_img2['ProcessGuid'].unique())
        except Exception:
            pass

    stats = {
        'total_sysmon_events':         total_sysmon_events,
        'matched_events':              matched_count,
        'matched_percentage':          matched_pct,
        'unique_violations':           len(unique_violation_processguids),
        'unique_processguids_matched': (df_matched['ProcessGuid'].nunique()
                                        if 'ProcessGuid' in df_matched.columns else 'N/A'),
        'output_file':                 str(output_file),
    }

    return True, "Éxito", stats


def main():
    parser = argparse.ArgumentParser(
        description='Extraer eventos Sysmon con violaciones de ProcessGuid',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python extract_violation_events.py --run 1
  python extract_violation_events.py --run 12

Prerequisitos:
  - Haber ejecutado: python find_processguid_pid_violations.py --run X
  - Y/o: python find_processguid_image_violations.py --run X
        """
    )

    parser.add_argument('--run', type=int, default=None,
                        help='Número de run a procesar (ej. 1 para run-01)')
    parser.add_argument('--all', action='store_true',
                        help='Procesar todos los runs que tengan archivos de violaciones')

    args = parser.parse_args()

    if args.run is None and not args.all:
        parser.error("Debe especificar --run o --all")

    print("=" * 80)
    print("Extraer eventos Sysmon con violaciones de ProcessGuid")
    print("=" * 80)

    if args.all:
        violation_files = sorted(DATASET_DIR.glob("run-*/04_processguid-pid-violations-run-*.csv"))
        run_numbers = []
        for vf in violation_files:
            match = re.search(r'run-(\d+)\.csv$', vf.name)
            if match:
                run_numbers.append(int(match.group(1)))
        if not run_numbers:
            print("❌ No se encontraron archivos de violaciones!")
            sys.exit(1)
        print(f"Encontrados {len(run_numbers)} runs: {run_numbers}")
    else:
        print(f"MODO: Run único (run-{args.run:02d})")
        run_numbers = [args.run]

    print("=" * 80)
    print()

    results = []
    for idx, run_num in enumerate(run_numbers, 1):
        if len(run_numbers) > 1:
            print(f"\n[{idx}/{len(run_numbers)}] Procesando run-{run_num:02d}")
            print("-" * 80)
        success, message, stats = extract_violation_events(run_num)
        results.append({'run': run_num, 'success': success, 'message': message, 'stats': stats})

    print()
    print("=" * 80)
    print("RESULTADOS")
    print("=" * 80)

    for result in results:
        run_label = f"run-{result['run']:02d}"
        if result['success']:
            stats = result['stats']
            print(f"✅ {run_label}")
            print(f"   Total eventos Sysmon:          {stats['total_sysmon_events']:,}")
            print(f"   Eventos con violaciones:       {stats['matched_events']:,} ({stats['matched_percentage']:.2f}%)")
            print(f"   ProcessGuids únicos (violac.): {stats['unique_violations']:,}")
            print(f"   Archivo de salida: {stats['output_file']}")
        else:
            print(f"❌ {run_label}: {result['message']}")
            if len(run_numbers) == 1:
                sys.exit(1)

    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()
