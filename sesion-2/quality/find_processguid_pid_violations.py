#!/usr/bin/env python3
"""
Script para identificar violaciones ProcessGuid → ProcessId (PID).

Comportamiento esperado: 1 ProcessGuid → exactamente 1 ProcessId.
Detecta GUIDs que mapean a N ProcessIds distintos (N > 1).

Salida: CSV con una fila por combinación única (ProcessGuid, ProcessId, Image, Computer)
        para los ProcessGuids que tienen múltiples PIDs.

Copia de trabajo de fullapt2025/scripts/pipeline/quality/find_processguid_pid_violations.py
adaptada para ejecutarse desde curso2026/sesion-2/quality/.
"""

import pandas as pd
from pathlib import Path
from collections import defaultdict
import re
import gc
import argparse

# Ruta al dataset — relativa a sesion-2/quality/
_SCRIPT_DIR = Path(__file__).resolve().parent
DATASET_DIR = _SCRIPT_DIR.parent.parent.parent / "fullapt2025" / "dataset"


def discover_runs():
    runs = []
    pattern = re.compile(r'^run-(\d+)-(apt-\d+)$')

    for item in sorted(DATASET_DIR.iterdir()):
        if item.is_dir():
            match = pattern.match(item.name)
            if match:
                run_num = int(match.group(1))
                apt_id = match.group(2)
                runs.append((run_num, apt_id, item))

    return runs


def find_violations(run_number=None):
    guid_to_info = defaultdict(set)

    all_runs = discover_runs()

    run_dir_out = None
    if run_number is not None:
        all_runs = [r for r in all_runs if r[0] == run_number]
        if not all_runs:
            print(f"❌ Run {run_number} no encontrado en el dataset!")
            return pd.DataFrame(columns=['ProcessGuid', 'ProcessId', 'Image', 'Computer', 'RunID']), None
        run_dir_out = all_runs[0][2]

    total_runs = len(all_runs)

    if run_number is not None:
        print(f"Procesando run único: run-{run_number:02d}")
    else:
        print(f"Encontrados {total_runs} runs de APT")
    print(f"Buscando violaciones ProcessGuid → ProcessId...")
    print("=" * 70)

    for idx, (run_num, apt_id, run_dir) in enumerate(all_runs, start=1):
        run_id = f"run-{run_num:02d}"
        sysmon_file = run_dir / f"02_sysmon-{run_id}.csv"

        if not sysmon_file.exists():
            print(f"  [{idx:2d}/{total_runs}] SKIP: {apt_id} {run_id} - archivo no encontrado")
            continue

        try:
            chunk_size = 100000
            total_rows = 0

            for chunk in pd.read_csv(
                sysmon_file,
                usecols=['ProcessGuid', 'ProcessId', 'Image', 'Computer'],
                dtype={'ProcessGuid': str, 'Image': str, 'Computer': str},
                chunksize=chunk_size,
                low_memory=False
            ):
                chunk = chunk.dropna(subset=['ProcessGuid', 'ProcessId'])
                total_rows += len(chunk)

                for guid in chunk['ProcessGuid'].unique():
                    guid_rows = chunk[chunk['ProcessGuid'] == guid]
                    for _, row in guid_rows.iterrows():
                        guid_to_info[guid].add((
                            row['ProcessId'],
                            row['Image'],
                            row['Computer'],
                            run_id
                        ))

                del chunk
                gc.collect()

            print(f"  [{idx:2d}/{total_runs}] OK:   {apt_id} {run_id} - {total_rows:,} filas procesadas")

        except Exception as e:
            print(f"  [{idx:2d}/{total_runs}] ERROR: {apt_id} {run_id} - {e}")
            continue

    print("=" * 70)
    print(f"Analizando {len(guid_to_info):,} ProcessGuids únicos...")

    violations = []

    for guid, info_set in guid_to_info.items():
        unique_pids = set(pid for pid, _, _, _ in info_set)

        if len(unique_pids) > 1:
            for pid, image, computer, run_id in info_set:
                violations.append({
                    'ProcessGuid': guid,
                    'ProcessId':   pid,
                    'Image':       image,
                    'Computer':    computer,
                    'RunID':       run_id,
                })

    if violations:
        df_violations = pd.DataFrame(violations)
        df_violations = df_violations.sort_values(['ProcessGuid', 'ProcessId', 'RunID'])
        return df_violations, run_dir_out
    else:
        return pd.DataFrame(columns=['ProcessGuid', 'ProcessId', 'Image', 'Computer', 'RunID']), run_dir_out


def main():
    parser = argparse.ArgumentParser(
        description='Detectar violaciones ProcessGuid → ProcessId',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python find_processguid_pid_violations.py --run 1
  python find_processguid_pid_violations.py
        """
    )
    parser.add_argument('--run', type=int, default=None,
                        help='Número de run (ej. 1 para run-01)')
    args = parser.parse_args()

    print("Detector de violaciones ProcessGuid → ProcessId")
    print("=" * 70)
    if args.run is not None:
        print(f"MODO: Run único (run-{args.run:02d})")
    else:
        print("MODO: Batch (todos los runs)")
    print("=" * 70)
    print()

    df_violations, run_dir = find_violations(run_number=args.run)

    if args.run is not None:
        output_file = run_dir / f"04_processguid-pid-violations-run-{args.run:02d}.csv"
    else:
        output_file = DATASET_DIR / "04_processguid-pid-violations-all.csv"

    print()
    print("=" * 70)
    print("RESULTADOS:")
    print("=" * 70)

    if len(df_violations) > 0:
        unique_guids = df_violations['ProcessGuid'].nunique()
        print(f"⚠️  VIOLACIONES ENCONTRADAS!")
        print(f"    - ProcessGuids únicos con violaciones: {unique_guids:,}")
        print(f"    - Total combinaciones (ProcessGuid, ProcessId): {len(df_violations):,}")
        print()
        print(f"Guardando en: {output_file}")
        df_violations.to_csv(output_file, index=False)
        print()
        print("Muestra (primeras 10 filas):")
        print(df_violations.head(10).to_string(index=False))
    else:
        print("✅ SIN VIOLACIONES!")
        print("   Todos los ProcessGuids mapean exactamente a 1 ProcessId.")
        print()
        print(f"Creando CSV vacío en: {output_file}")
        df_violations.to_csv(output_file, index=False)

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
