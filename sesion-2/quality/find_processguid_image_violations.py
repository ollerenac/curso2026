#!/usr/bin/env python3
"""
Script para identificar violaciones ProcessGuid → Image.

Comportamiento esperado: 1 ProcessGuid → exactamente 1 Image.
Detecta GUIDs que mapean a N Images distintas (N > 1).
La comparación de Image es CASE-INSENSITIVE (rutas Windows).

Salida: CSV con una fila por combinación única (ProcessGuid, Image, ProcessId, Computer)
        para los ProcessGuids que tienen múltiples Images.

Copia de trabajo de fullapt2025/scripts/pipeline/quality/find_processguid_image_violations.py
adaptada para ejecutarse desde curso2026/sesion-2/quality/.
"""

import pandas as pd
from pathlib import Path
from collections import defaultdict
import re
import gc
import sys
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


def find_violations(output_file, resume=False, run_number=None):
    guid_to_info = defaultdict(set)
    processed_runs = set()

    if resume and output_file.exists():
        print(f"Modo resume: cargando violaciones existentes de {output_file}")
        try:
            existing = pd.read_csv(output_file)
            if len(existing) > 0:
                processed_runs = set(existing['RunID'].unique())
                print(f"  Encontrados {len(processed_runs)} runs ya procesados")
                for _, row in existing.iterrows():
                    guid_to_info[row['ProcessGuid']].add((
                        row['Image'],
                        row['ProcessId'],
                        row['Computer'],
                        row['RunID']
                    ))
        except Exception as e:
            print(f"  Advertencia: no se pudo cargar el archivo existente: {e}")
            print(f"  Iniciando desde cero...")

    all_runs = discover_runs()

    run_dir_out = None
    if run_number is not None:
        all_runs = [r for r in all_runs if r[0] == run_number]
        if not all_runs:
            print(f"❌ Run {run_number} no encontrado en el dataset!")
            return pd.DataFrame(columns=['ProcessGuid', 'Image', 'ProcessId', 'Computer', 'RunID']), None
        run_dir_out = all_runs[0][2]

    total_runs = len(all_runs)
    runs_to_process = [r for r in all_runs if f"run-{r[0]:02d}" not in processed_runs]

    if run_number is not None:
        print(f"Procesando run único: run-{run_number:02d}")
    else:
        print(f"Encontrados {total_runs} runs de APT")
        if resume:
            print(f"Saltando {len(processed_runs)} runs ya procesados")
            print(f"Procesando {len(runs_to_process)} runs restantes")
    print(f"Buscando violaciones ProcessGuid → Image...")
    print("=" * 70)
    sys.stdout.flush()

    for idx, (run_num, apt_id, run_dir) in enumerate(all_runs, start=1):
        run_id = f"run-{run_num:02d}"

        if resume and run_id in processed_runs:
            print(f"  [{idx:2d}/{total_runs}] SKIP: {apt_id} {run_id} - ya procesado")
            continue

        sysmon_file = run_dir / f"02_sysmon-{run_id}.csv"

        if not sysmon_file.exists():
            print(f"  [{idx:2d}/{total_runs}] SKIP: {apt_id} {run_id} - archivo no encontrado")
            continue

        try:
            chunk_size = 100000
            total_rows = 0

            for chunk in pd.read_csv(
                sysmon_file,
                usecols=['ProcessGuid', 'Image', 'ProcessId', 'Computer'],
                dtype={'ProcessGuid': str, 'Image': str, 'Computer': str},
                chunksize=chunk_size,
                low_memory=False
            ):
                chunk = chunk.dropna(subset=['ProcessGuid', 'Image'])
                total_rows += len(chunk)

                for guid in chunk['ProcessGuid'].unique():
                    guid_rows = chunk[chunk['ProcessGuid'] == guid]
                    for _, row in guid_rows.iterrows():
                        guid_to_info[guid].add((
                            row['Image'],
                            row['ProcessId'],
                            row['Computer'],
                            run_id
                        ))

                del chunk
                gc.collect()

            print(f"  [{idx:2d}/{total_runs}] OK:   {apt_id} {run_id} - {total_rows:,} filas procesadas")
            sys.stdout.flush()

        except Exception as e:
            print(f"  [{idx:2d}/{total_runs}] ERROR: {apt_id} {run_id} - {e}")
            sys.stdout.flush()
            continue

    print("=" * 70)
    print(f"Analizando {len(guid_to_info):,} ProcessGuids únicos...")
    sys.stdout.flush()

    violations = []

    for guid, info_set in guid_to_info.items():
        unique_images_normalized = set(
            image.lower() if pd.notna(image) else '' for image, _, _, _ in info_set
        )

        if len(unique_images_normalized) > 1:
            for image, pid, computer, run_id in info_set:
                violations.append({
                    'ProcessGuid': guid,
                    'Image':       image,
                    'ProcessId':   pid,
                    'Computer':    computer,
                    'RunID':       run_id,
                })

    if violations:
        df_violations = pd.DataFrame(violations)
        df_violations = df_violations.sort_values(['ProcessGuid', 'Image', 'RunID'])
        return df_violations, run_dir_out
    else:
        return pd.DataFrame(columns=['ProcessGuid', 'Image', 'ProcessId', 'Computer', 'RunID']), run_dir_out


def main():
    parser = argparse.ArgumentParser(
        description='Detectar violaciones ProcessGuid → Image',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python find_processguid_image_violations.py --run 1
  python find_processguid_image_violations.py
  python find_processguid_image_violations.py --resume
        """
    )
    parser.add_argument('--run', type=int, default=None,
                        help='Número de run (ej. 1 para run-01)')
    parser.add_argument('--resume', action='store_true',
                        help='Reanudar desde un run batch interrumpido (solo modo batch)')
    args = parser.parse_args()

    if args.run is not None:
        target_runs = [r for r in discover_runs() if r[0] == args.run]
        if not target_runs:
            print(f"❌ Run {args.run} no encontrado en el dataset!")
            return
        run_dir = target_runs[0][2]
        output_file = run_dir / f"04_processguid-image-violations-run-{args.run:02d}.csv"
    else:
        output_file = DATASET_DIR / "04_processguid-image-violations-all.csv"

    print("Detector de violaciones ProcessGuid → Image")
    print("=" * 70)
    if args.run is not None:
        print(f"MODO: Run único (run-{args.run:02d})")
    elif args.resume:
        print("MODO: Batch con RESUME")
    else:
        print("MODO: Batch (todos los runs)")
    print("=" * 70)
    print()

    df_violations, _ = find_violations(output_file, resume=args.resume, run_number=args.run)

    print()
    print("=" * 70)
    print("RESULTADOS:")
    print("=" * 70)

    if len(df_violations) > 0:
        unique_guids = df_violations['ProcessGuid'].nunique()
        print(f"⚠️  VIOLACIONES ENCONTRADAS!")
        print(f"    - ProcessGuids únicos con violaciones: {unique_guids:,}")
        print(f"    - Total combinaciones (ProcessGuid, Image): {len(df_violations):,}")
        print()
        print(f"Guardando en: {output_file}")
        df_violations.to_csv(output_file, index=False)
        print()
        print("Muestra (primeras 10 filas):")
        print(df_violations.head(10).to_string(index=False))
        print()
        print("Top 10 ProcessGuids por número de Images distintas:")
        guid_counts = df_violations.groupby('ProcessGuid')['Image'].nunique().sort_values(ascending=False).head(10)
        for guid, count in guid_counts.items():
            print(f"  {guid}: {count} Images distintas")
    else:
        print("✅ SIN VIOLACIONES!")
        print("   Todos los ProcessGuids mapean exactamente a 1 Image.")
        print()
        print(f"Creando CSV vacío en: {output_file}")
        df_violations.to_csv(output_file, index=False)

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
