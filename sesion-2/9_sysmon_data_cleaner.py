#!/usr/bin/env python3
"""
Sesión 2 / Sección 9: Sysmon Data Quality Fixer

Orquestador del pipeline de limpieza de datos Sysmon.
Copia de trabajo de fullapt2025/scripts/pipeline/4_sysmon_data_cleaner.py
adaptada para ejecutarse desde curso2026/sesion-2/.

Workflow:
1. Detectar violaciones ProcessGuid → PID
2. Detectar violaciones ProcessGuid → Image
3. Normalizar duplicados de ruta (eliminar prefijo \\?\)
4. Extraer eventos con violaciones a archivo separado
5. Edición manual (pausa interactiva o salto automático)
6. Aplicar correcciones al CSV Sysmon original

Uso:
    # Workflow completo interactivo (por defecto)
    python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01

    # Solo detectar violaciones (para inspección)
    python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --detect-only

    # Solo aplicar correcciones (asumiendo que el archivo ya fue editado)
    python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --apply-only

    # Saltar normalización
    python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --skip-normalization

    # Dry run (previsualizar cambios sin aplicar)
    python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --dry-run
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path

# Directorios — rutas relativas a sesion-2/
SESION_DIR = Path(__file__).parent
QUALITY_DIR = SESION_DIR / "quality"
DATASET_DIR = SESION_DIR.parent.parent / "fullapt2025" / "dataset"

# Scripts de calidad (en sesion-2/quality/)
DETECT_PID_SCRIPT   = QUALITY_DIR / "find_processguid_pid_violations.py"
DETECT_IMAGE_SCRIPT = QUALITY_DIR / "find_processguid_image_violations.py"
NORMALIZE_SCRIPT    = QUALITY_DIR / "normalize_path_duplicates.py"
EXTRACT_SCRIPT      = QUALITY_DIR / "extract_violation_events.py"
APPLY_SCRIPT        = QUALITY_DIR / "apply_violation_fixes.py"


def print_header(title):
    print()
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)
    print()


def run_command(cmd, description, check=True):
    print(f"▶ {description}...")
    print(f"  Command: {' '.join(str(c) for c in cmd)}")
    print()

    result = subprocess.run(cmd, check=False)

    if check and result.returncode != 0:
        print(f"\n❌ ERROR: {description} failed with exit code {result.returncode}")
        sys.exit(1)

    print()
    return result.returncode == 0


def get_run_number(run_id):
    return int(run_id)


def get_violations_file(apt_type, run_id):
    run_dir = DATASET_DIR / f"run-{run_id}-{apt_type}"
    return run_dir / f"04_sysmon-run-{run_id}-violations.csv"


def get_violation_detection_files(apt_type, run_id):
    run_num = get_run_number(run_id)
    run_dir = DATASET_DIR / f"run-{run_id}-{apt_type}"
    return {
        'pid':              run_dir / f"04_processguid-pid-violations-run-{run_num:02d}.csv",
        'image':            run_dir / f"04_processguid-image-violations-run-{run_num:02d}.csv",
        'image_normalized': run_dir / f"04_processguid-image-violations-run-{run_num:02d}_normalized.csv",
    }


def detect_violations(run_id):
    print_header("PASO 1-2: Detectando violaciones de ProcessGuid")

    run_num = get_run_number(run_id)

    success = run_command(
        ["python3", str(DETECT_PID_SCRIPT), "--run", str(run_num)],
        "Detectando violaciones ProcessGuid → PID"
    )

    success = run_command(
        ["python3", str(DETECT_IMAGE_SCRIPT), "--run", str(run_num)],
        "Detectando violaciones ProcessGuid → Image"
    ) and success

    return success


def normalize_violations(apt_type, run_id, skip_normalization=False):
    if skip_normalization:
        print_header("PASO 3: Normalización de rutas (SALTADO)")
        print("⊘ Normalización saltada (--skip-normalization)")
        return True

    print_header("PASO 3: Normalización de rutas")

    files = get_violation_detection_files(apt_type, run_id)
    image_violations = files['image']

    if not image_violations.exists():
        print(f"⊘ Archivo de violaciones Image no encontrado: {image_violations}")
        print("  Saltando normalización...")
        return True

    success = run_command(
        ["python3", str(NORMALIZE_SCRIPT), str(image_violations)],
        "Normalizando violaciones Image (eliminando prefijo \\\\?\\)"
    )

    if success:
        normalized = files['image_normalized']
        if normalized.exists():
            print(f"▶ Reemplazando original con versión normalizada...")
            os.rename(normalized, image_violations)
            print(f"  ✓ {image_violations}")

    return success


def extract_violations(run_id):
    print_header("PASO 4: Extrayendo eventos con violaciones")

    run_num = get_run_number(run_id)

    success = run_command(
        ["python3", str(EXTRACT_SCRIPT), "--run", str(run_num)],
        "Extrayendo eventos con violaciones a archivo separado"
    )

    return success


def manual_editing_pause(violations_file, auto_skip=False):
    print_header("PASO 5: Edición manual")

    if not violations_file.exists():
        print(f"❌ Archivo de violaciones no encontrado: {violations_file}")
        return False

    if auto_skip:
        print("⊘ Modo automático: saltando edición manual")
        print(f"  Usando archivo existente: {violations_file}")
        return True

    print(f"📝 Archivo de violaciones listo para editar:")
    print(f"   {violations_file}")
    print()
    print("Instrucciones de edición:")
    print("  1. Abrir en LibreOffice/Excel")
    print("  2. Corregir valores de ProcessGuid, Image, u otras columnas")
    print("  3. Eliminar filas que quieras descartar")
    print("  4. NO modificar _original_row_index ni _row_hash")
    print("  5. Guardar y cerrar el archivo")
    print()

    print("▶ Intentando abrir LibreOffice...")
    try:
        subprocess.Popen(
            ["libreoffice", "--calc", str(violations_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("  ✓ LibreOffice abierto")
        print()
        print("⏸  Esperando a que termines la edición...")
        print("   Pulsa Enter cuando hayas guardado y cerrado el archivo...")
    except FileNotFoundError:
        print("  ⊘ LibreOffice no encontrado, ábrelo manualmente")
        print()
        print("⏸  Pulsa Enter cuando hayas terminado la edición...")

    input()
    print("  ✓ Continuando...")

    return True


def apply_fixes(run_id, dry_run=False, verbose=False):
    print_header("PASO 6: Aplicando correcciones al CSV Sysmon original")

    run_num = get_run_number(run_id)

    cmd = ["python3", str(APPLY_SCRIPT), "--run", str(run_num)]

    if dry_run:
        cmd.append("--dry-run")
        description = "Previsualización de correcciones (DRY RUN — sin cambios)"
    else:
        if verbose:
            cmd.append("--verbose")
        description = "Aplicando correcciones al CSV Sysmon original"

    success = run_command(cmd, description)

    return success


def verify_prerequisites(apt_type, run_id):
    print_header("Verificando prerequisitos")

    run_dir = DATASET_DIR / f"run-{run_id}-{apt_type}"
    sysmon_file = run_dir / f"02_sysmon-run-{run_id}.csv"

    print(f"▶ Buscando CSV Sysmon...")
    if not sysmon_file.exists():
        print(f"  ❌ NO ENCONTRADO: {sysmon_file}")
        print()
        print("Ejecuta primero los pasos 1-3 del pipeline:")
        print("  1. python 1_elastic_index_downloader.py")
        print(f"  2. python 2_sysmon_csv_creator.py --apt-type {apt_type} --run-id {run_id}")
        print(f"  3. python 3_netflow_csv_creator.py --apt-type {apt_type} --run-id {run_id}")
        return False

    print(f"  ✓ ENCONTRADO: {sysmon_file}")

    print(f"\n▶ Verificando scripts de calidad en {QUALITY_DIR}...")
    scripts_ok = True
    for script_name, script_path in [
        ("Detector PID",    DETECT_PID_SCRIPT),
        ("Detector Image",  DETECT_IMAGE_SCRIPT),
        ("Normalizador",    NORMALIZE_SCRIPT),
        ("Extractor",       EXTRACT_SCRIPT),
        ("Aplicador",       APPLY_SCRIPT),
    ]:
        if not script_path.exists():
            print(f"  ❌ FALTA: {script_name} en {script_path}")
            scripts_ok = False
        else:
            print(f"  ✓ {script_name}")

    if not scripts_ok:
        print("\n❌ Faltan scripts de calidad. Verifica el directorio quality/.")
        return False

    print("\n✅ Todos los prerequisitos satisfechos")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Sesión 2 / Sección 9: Sysmon Data Quality Fixer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Workflow completo interactivo
  python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01

  # Solo detección (para inspección)
  python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --detect-only

  # Solo aplicar correcciones (edición manual ya realizada)
  python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --apply-only

  # Saltar normalización
  python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --skip-normalization

  # Dry run (previsualizar sin aplicar)
  python 9_sysmon_data_cleaner.py --apt-type apt-1 --run-id 01 --dry-run
        """
    )

    parser.add_argument('--apt-type', required=True,
                        help='Tipo de APT (ej. apt-1, apt-2)')
    parser.add_argument('--run-id', required=True,
                        help='ID del run (ej. 01, 04)')
    parser.add_argument('--detect-only', action='store_true',
                        help='Solo detectar violaciones, no extraer ni aplicar')
    parser.add_argument('--apply-only', action='store_true',
                        help='Solo aplicar correcciones (asume que el archivo ya fue editado)')
    parser.add_argument('--skip-normalization', action='store_true',
                        help='Saltar el paso de normalización de rutas')
    parser.add_argument('--dry-run', action='store_true',
                        help='Previsualizar correcciones sin aplicar (implica --apply-only)')
    parser.add_argument('--verbose', action='store_true',
                        help='Mostrar cambios detallados al aplicar correcciones')

    args = parser.parse_args()

    print()
    print("=" * 80)
    print("  SESIÓN 2 / SECCIÓN 9: SYSMON DATA QUALITY FIXER")
    print("=" * 80)
    print(f"  APT Type: {args.apt_type}")
    print(f"  Run ID:   {args.run_id}")
    print(f"  Dataset:  {DATASET_DIR}")
    print("=" * 80)

    if not verify_prerequisites(args.apt_type, args.run_id):
        sys.exit(1)

    violations_file = get_violations_file(args.apt_type, args.run_id)

    if args.dry_run:
        args.apply_only = True

    try:
        if not args.apply_only:
            if not detect_violations(args.run_id):
                print("\n❌ Detección de violaciones fallida")
                sys.exit(1)

            if args.detect_only:
                print_header("COMPLETO (Solo detección)")
                print("✅ Detección de violaciones completada")
                print()
                print("Próximos pasos:")
                print("  1. Revisar los archivos de violaciones en el directorio del run")
                print("  2. Ejecutar sin --detect-only para extraer y corregir")
                sys.exit(0)

            if not normalize_violations(args.apt_type, args.run_id, args.skip_normalization):
                print("\n❌ Normalización fallida")
                sys.exit(1)

            if not extract_violations(args.run_id):
                print("\n❌ Extracción fallida")
                sys.exit(1)

            if not manual_editing_pause(violations_file):
                print("\n❌ Paso de edición manual fallido")
                sys.exit(1)

        else:
            print_header("MODO: Solo aplicar")
            print("Saltando detección, normalización, extracción y edición...")
            print(f"Usando archivo existente: {violations_file}")

            if not violations_file.exists():
                print(f"\n❌ Archivo de violaciones no encontrado: {violations_file}")
                print("   Ejecuta sin --apply-only para generarlo primero")
                sys.exit(1)

        if not apply_fixes(args.run_id, args.dry_run, args.verbose):
            print("\n❌ Aplicación de correcciones fallida")
            sys.exit(1)

        print_header("✅ COMPLETO")

        if args.dry_run:
            print("Dry run completado. Ejecuta sin --dry-run para aplicar los cambios.")
        else:
            print("Limpieza de datos completada exitosamente.")
            print()
            print("Próximos pasos:")
            print("  • Verificar que las correcciones se aplicaron correctamente")
            print("  • Continuar con la Sección 10 (NetFlow) o Sesión 3 (correlación)")

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrumpido por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
