#!/usr/bin/env python3
"""
Detectar violaciones ProcessGuid → ProcessId (Invariante 1) en los cuatro pares k.

  k=1  ProcessGuid       / ProcessId       (EID ∉ {8, 10})
  k=2  ParentProcessGuid / ParentProcessId (EID = 1)
  k=3  SourceProcessGUID / SourceProcessId (EID ∈ {8, 10})
  k=4  TargetProcessGUID / TargetProcessId (EID ∈ {8, 10})

Salida: una fila por (GUID, PID, Image, Computer) único con columnas de metadato
        k_pair, guid_col, pid_col para uso por extract_violation_events.py.

Copia de trabajo de fullapt2025/scripts/pipeline/quality/find_processguid_pid_violations.py
adaptada para ejecutarse desde curso2026/sesion-2/quality/.

Uso:
    python find_processguid_pid_violations.py --run 1
    python find_processguid_pid_violations.py
"""

import pandas as pd
from pathlib import Path
from collections import defaultdict
import re
import gc
import argparse

# Ruta al dataset — relativa a sesion-2/quality/
_SCRIPT_DIR = Path(__file__).resolve().parent
DATASET_DIR = _SCRIPT_DIR.parent.parent / "dataset"

PAIRS = [
    (1, 'ProcessGuid',       'ProcessId',       'Image',       'eid_not_8_10'),
    (2, 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'eid_eq_1'),
    (3, 'SourceProcessGUID', 'SourceProcessId', 'SourceImage', 'eid_8_10'),
    (4, 'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'eid_8_10'),
]

DOMAIN_FILTER = {
    'eid_not_8_10': lambda d: d[~d['EventID'].isin([8, 10])],
    'eid_eq_1':     lambda d: d[d['EventID'] == 1],
    'eid_8_10':     lambda d: d[d['EventID'].isin([8, 10])],
}

READ_COLS = [
    'EventID', 'Computer',
    'ProcessGuid',       'ProcessId',       'Image',
    'ParentProcessGuid', 'ParentProcessId', 'ParentImage',
    'SourceProcessGUID', 'SourceProcessId', 'SourceImage',
    'TargetProcessGUID', 'TargetProcessId', 'TargetImage',
]


def discover_runs():
    runs = []
    pattern = re.compile(r'^run-(\d+)-(apt-\d+)$')
    for item in sorted(DATASET_DIR.iterdir()):
        if item.is_dir():
            m = pattern.match(item.name)
            if m:
                runs.append((int(m.group(1)), m.group(2), item))
    return runs


def _empty_df():
    return pd.DataFrame(columns=[
        'k_pair', 'guid_col', 'pid_col',
        'ProcessGuid', 'ProcessId', 'Image', 'Computer', 'RunID',
    ])


def _accumulate(chunk, accumulators, run_id):
    for k, guid_col, pid_col, img_col, domain_key in PAIRS:
        if guid_col not in chunk.columns or pid_col not in chunk.columns:
            continue

        domain = DOMAIN_FILTER[domain_key](chunk)
        cols = [c for c in [guid_col, pid_col, img_col, 'Computer'] if c in domain.columns]
        valid = domain[cols].dropna(subset=[guid_col, pid_col]).copy()

        if img_col not in valid.columns:
            valid[img_col] = ''
        else:
            valid[img_col] = valid[img_col].fillna('')

        for _, row in valid.iterrows():
            accumulators[k][row[guid_col]].add((
                row[pid_col], row[img_col], row['Computer'], run_id
            ))


def _detect(accumulators):
    violations = []
    for k, guid_col, pid_col, img_col, _ in PAIRS:
        for guid, info_set in accumulators[k].items():
            unique_pids = {pid for pid, _, _, _ in info_set}
            if len(unique_pids) > 1:
                for pid, image, computer, run_id in info_set:
                    violations.append({
                        'k_pair':      k,
                        'guid_col':    guid_col,
                        'pid_col':     pid_col,
                        'ProcessGuid': guid,
                        'ProcessId':   pid,
                        'Image':       image,
                        'Computer':    computer,
                        'RunID':       run_id,
                    })
    if violations:
        return (pd.DataFrame(violations)
                .sort_values(['k_pair', 'ProcessGuid', 'ProcessId', 'RunID'])
                .reset_index(drop=True))
    return _empty_df()


def find_violations(run_number=None):
    # Un acumulador por par k: guid → set de (PID, Image, Computer, RunID)
    accumulators = {k: defaultdict(set) for k, *_ in PAIRS}

    all_runs = discover_runs()
    run_dir_out = None
    if run_number is not None:
        all_runs = [r for r in all_runs if r[0] == run_number]
        if not all_runs:
            print(f"❌ Run {run_number} no encontrado en el dataset!")
            return _empty_df(), None
        run_dir_out = all_runs[0][2]

    total_runs = len(all_runs)
    if run_number is not None:
        print(f"Procesando run único: run-{run_number:02d}")
    else:
        print(f"Encontrados {total_runs} runs de APT")
    print("Buscando violaciones ProcessGuid → ProcessId en los 4 pares k...")
    print("=" * 70)

    for idx, (run_num, apt_id, run_dir) in enumerate(all_runs, start=1):
        run_id = f"run-{run_num:02d}"
        sysmon_file = run_dir / f"02_sysmon-{run_id}.csv"

        if not sysmon_file.exists():
            print(f"  [{idx:2d}/{total_runs}] SKIP: {apt_id} {run_id} — archivo no encontrado")
            continue

        try:
            available = set(pd.read_csv(sysmon_file, nrows=0).columns)
            usecols = [c for c in READ_COLS if c in available]

            total_rows = 0
            for chunk in pd.read_csv(
                sysmon_file,
                usecols=usecols,
                chunksize=100_000,
                low_memory=False,
            ):
                total_rows += len(chunk)
                _accumulate(chunk, accumulators, run_id)
                del chunk
                gc.collect()

            print(f"  [{idx:2d}/{total_runs}] OK:   {apt_id} {run_id} — {total_rows:,} filas")

        except Exception as e:
            print(f"  [{idx:2d}/{total_runs}] ERROR: {apt_id} {run_id} — {e}")
            continue

    print("=" * 70)
    print(f"Analizando {sum(len(v) for v in accumulators.values()):,} entradas acumuladas...")

    return _detect(accumulators), run_dir_out


def main():
    parser = argparse.ArgumentParser(
        description='Detectar violaciones ProcessGuid → ProcessId (Invariante 1) — 4 pares k',
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

    print("Detector de violaciones ProcessGuid → ProcessId (Invariante 1 — 4 pares k)")
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
        print(f"⚠️  VIOLACIONES ENCONTRADAS!")
        print()
        for k in df_violations['k_pair'].unique():
            k_df     = df_violations[df_violations['k_pair'] == k]
            guid_col = k_df['guid_col'].iloc[0]
            pid_col  = k_df['pid_col'].iloc[0]
            print(f"  k={k}  {guid_col} / {pid_col}")
            print(f"       ProcessGuids violadores: {k_df['ProcessGuid'].nunique():,}")
            print(f"       Filas en CSV:            {len(k_df):,}")
        print()
        print(f"Guardando en: {output_file}")
        df_violations.to_csv(output_file, index=False)
        print()
        print("Muestra (primeras 10 filas):")
        print(df_violations.head(10).to_string(index=False))
    else:
        print("✅ SIN VIOLACIONES en ningún par k")
        print()
        print(f"Creando CSV vacío en: {output_file}")
        df_violations.to_csv(output_file, index=False)

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
