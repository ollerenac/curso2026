#!/usr/bin/env python3
"""
Aplicar correcciones del archivo de violaciones al CSV Sysmon original.

Lee el 04_sysmon-run-XX-violations.csv editado manualmente y aplica
los cambios de vuelta al 02_sysmon-run-XX.csv original.

Mecanismos de seguridad:
- Usa _original_row_index para localizar cada fila
- Verifica _row_hash antes de aplicar cambios (integridad)
- Crea backup automático antes de modificar
- Soporta --dry-run para previsualización sin cambios

Copia de trabajo de fullapt2025/scripts/pipeline/quality/apply_violation_fixes.py
adaptada para ejecutarse desde curso2026/sesion-2/quality/.

Uso:
    python apply_violation_fixes.py --run 1
    python apply_violation_fixes.py --run 1 --dry-run
"""

import pandas as pd
from pathlib import Path
import argparse
import sys
import hashlib
import re
from datetime import datetime
import shutil

# Ruta al dataset — relativa a sesion-2/quality/
_SCRIPT_DIR = Path(__file__).resolve().parent
DATASET_DIR = _SCRIPT_DIR.parent.parent.parent / "fullapt2025" / "dataset"


def discover_run_dir(run_number):
    pattern = re.compile(r'^run-(\d+)-(apt-\d+)$')

    for item in sorted(DATASET_DIR.iterdir()):
        if item.is_dir():
            match = pattern.match(item.name)
            if match:
                run_num = int(match.group(1))
                if run_num == run_number:
                    return item
    return None


def compute_row_hash(row):
    cols_to_hash = sorted([col for col in row.index if not col.startswith('_')])
    hash_input = '_'.join([str(row.get(col, '')) for col in cols_to_hash])
    return 'h' + hashlib.md5(hash_input.encode()).hexdigest()[:8]


def apply_fixes(run_number, dry_run=False):
    run_dir = discover_run_dir(run_number)
    if run_dir is None:
        return False, f"Directorio del run no encontrado para run-{run_number:02d}", {}

    violations_file = run_dir / f"04_sysmon-run-{run_number:02d}-violations.csv"
    original_file   = run_dir / f"02_sysmon-run-{run_number:02d}.csv"
    backup_file     = run_dir / f"02_sysmon-run-{run_number:02d}.csv.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if not violations_file.exists():
        return False, f"Archivo de violaciones no encontrado: {violations_file}", {}

    if not original_file.exists():
        return False, f"Archivo Sysmon original no encontrado: {original_file}", {}

    print(f"Cargando archivo de violaciones: {violations_file}")
    try:
        df_violations = pd.read_csv(
            violations_file,
            dtype={'_row_hash': str, '_original_row_index': int},
            low_memory=False
        )
    except Exception as e:
        return False, f"Error cargando el archivo de violaciones: {e}", {}

    if '_original_row_index' not in df_violations.columns:
        return False, "Falta la columna '_original_row_index'. Re-extraer con el script actualizado.", {}

    if '_row_hash' not in df_violations.columns:
        return False, "Falta la columna '_row_hash'. Re-extraer con el script actualizado.", {}

    print(f"  Cargadas {len(df_violations):,} filas de violaciones")

    print(f"\nCargando CSV Sysmon original: {original_file}")
    print("  (Puede tardar unos minutos para archivos grandes...)")
    try:
        df_original = pd.read_csv(original_file, low_memory=False)
    except Exception as e:
        return False, f"Error cargando el archivo original: {e}", {}

    print(f"  Cargadas {len(df_original):,} filas")

    max_index = df_violations['_original_row_index'].max()
    if max_index >= len(df_original):
        return False, f"Índice de fila inválido {max_index} (el archivo original tiene {len(df_original)} filas)", {}

    print(f"\nVerificando y aplicando correcciones...")

    changes_made    = []
    hash_mismatches = []
    rows_updated    = 0

    for idx, viol_row in df_violations.iterrows():
        orig_idx      = int(viol_row['_original_row_index'])
        expected_hash = viol_row['_row_hash']

        orig_row     = df_original.iloc[orig_idx]
        current_hash = compute_row_hash(orig_row)

        if current_hash != expected_hash:
            hash_mismatches.append({
                'violation_row':       idx,
                'original_row_index':  orig_idx,
                'expected_hash':       expected_hash,
                'current_hash':        current_hash,
            })
            continue

        row_changes = {}
        for col in df_violations.columns:
            if col.startswith('_'):
                continue
            if col not in df_original.columns:
                continue

            viol_value = viol_row[col]
            orig_value = orig_row[col]

            if pd.isna(viol_value) and pd.isna(orig_value):
                continue

            if viol_value != orig_value:
                row_changes[col] = {'old': orig_value, 'new': viol_value}

        if row_changes:
            if not dry_run:
                for col, change in row_changes.items():
                    df_original.at[orig_idx, col] = change['new']

            rows_updated += 1
            changes_made.append({'row_index': orig_idx, 'changes': row_changes})

    print(f"\n  Filas verificadas:            {len(df_violations):,}")
    print(f"  Filas con hash válido:        {len(df_violations) - len(hash_mismatches):,}")
    print(f"  Filas con hash incorrecto:    {len(hash_mismatches):,}")
    print(f"  Filas con cambios aplicados:  {rows_updated:,}")

    if hash_mismatches:
        print(f"\n  ⚠️  ADVERTENCIA: {len(hash_mismatches)} filas saltadas por hash incorrecto!")
        print("  El CSV original fue modificado después de la extracción.")
        for mm in hash_mismatches[:5]:
            print(f"    Fila {mm['original_row_index']}: hash esperado {mm['expected_hash']}, obtenido {mm['current_hash']}")
        if len(hash_mismatches) > 5:
            print(f"    ... y {len(hash_mismatches) - 5} más")

    if not dry_run and rows_updated > 0:
        print(f"\nCreando backup: {backup_file}")
        try:
            shutil.copy2(original_file, backup_file)
            print("  ✅ Backup creado")
        except Exception as e:
            return False, f"Error creando backup: {e}", {}

        print(f"\nGuardando archivo actualizado: {original_file}")
        try:
            df_original.to_csv(original_file, index=False)
            print("  ✅ Archivo actualizado")
        except Exception as e:
            return False, f"Error guardando el archivo actualizado: {e}", {}

    stats = {
        'total_violation_rows': len(df_violations),
        'rows_verified':        len(df_violations) - len(hash_mismatches),
        'hash_mismatches':      len(hash_mismatches),
        'rows_updated':         rows_updated,
        'changes_made':         changes_made,
        'backup_file':          str(backup_file) if not dry_run and rows_updated > 0 else None,
        'dry_run':              dry_run,
    }

    return True, "Éxito", stats


def main():
    parser = argparse.ArgumentParser(
        description='Aplicar correcciones al CSV Sysmon original',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python apply_violation_fixes.py --run 1
  python apply_violation_fixes.py --run 1 --dry-run
  python apply_violation_fixes.py --run 1 --verbose

Prerequisitos:
  - Haber ejecutado: python extract_violation_events.py --run X
  - Haber editado manualmente el archivo 04_sysmon-run-XX-violations.csv
        """
    )

    parser.add_argument('--run', type=int, required=True,
                        help='Número de run a procesar (ej. 1 para run-01)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Previsualizar cambios sin aplicarlos')
    parser.add_argument('--verbose', action='store_true',
                        help='Mostrar log detallado de cambios')

    args = parser.parse_args()

    print("=" * 80)
    print("Aplicar correcciones al CSV Sysmon original")
    print("=" * 80)
    print(f"Run: run-{args.run:02d}")
    if args.dry_run:
        print("MODO: DRY RUN (solo previsualización, sin cambios)")
    else:
        print("MODO: APLICAR CORRECCIONES (modificará el archivo original)")
    print("=" * 80)
    print()

    success, message, stats = apply_fixes(args.run, dry_run=args.dry_run)

    print()
    print("=" * 80)
    print("RESULTADOS")
    print("=" * 80)

    if success:
        if stats['dry_run']:
            print("✅ DRY RUN COMPLETO (sin cambios aplicados)")
        else:
            print("✅ CORRECCIONES APLICADAS EXITOSAMENTE")

        print()
        print(f"Filas de violaciones totales:  {stats['total_violation_rows']:,}")
        print(f"Filas verificadas (hash OK):   {stats['rows_verified']:,}")
        print(f"Hash incorrectos (saltadas):   {stats['hash_mismatches']:,}")
        print(f"Filas con cambios:             {stats['rows_updated']:,}")

        if stats['backup_file']:
            print()
            print(f"Backup creado: {stats['backup_file']}")
            print()
            print("Para revertir los cambios:")
            print(f"  cp {stats['backup_file']} 02_sysmon-run-{args.run:02d}.csv")

        if args.verbose and stats['changes_made']:
            print()
            print("=" * 80)
            print("LOG DE CAMBIOS DETALLADO")
            print("=" * 80)

            for change in stats['changes_made'][:20]:
                print(f"\nFila {change['row_index']}:")
                for col, vals in change['changes'].items():
                    print(f"  {col}:")
                    print(f"    Antes: {vals['old']}")
                    print(f"    Después: {vals['new']}")

            if len(stats['changes_made']) > 20:
                print(f"\n... y {len(stats['changes_made']) - 20} filas más con cambios")

        if stats['rows_updated'] == 0:
            print()
            print("ℹ️  Sin cambios detectados en el archivo de violaciones")
            print("   (Todas las filas coinciden con el original)")

    else:
        print("❌ FALLIDO")
        print()
        print(f"Error: {message}")
        sys.exit(1)

    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()
