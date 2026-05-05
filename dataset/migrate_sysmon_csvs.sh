#!/bin/bash
# migrate_sysmon_csvs.sh
# Copies 02_sysmon-run-XX.csv from fullapt2025/dataset to curso2026/dataset.
# Verifies each copy with MD5. Does NOT delete the source.

SRC_ROOT="/home/researcher/Research/phd-thesis/fullapt2025/dataset"
DST_ROOT="/home/researcher/Research/phd-thesis/curso2026/dataset"
LOG_FILE="$DST_ROOT/sysmon_migration.log"

counters_ok=0
counters_skip=0
counters_exists=0
counters_error=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Sysmon CSV migration started ==="
log "SRC: $SRC_ROOT"
log "DST: $DST_ROOT"

for run_dir in "$SRC_ROOT"/run-*/; do
    run_name=$(basename "$run_dir")
    csv_file=$(ls "$run_dir"02_sysmon-run-*.csv 2>/dev/null | head -1)

    if [ -z "$csv_file" ]; then
        log "[SKIP] $run_name: no 02_sysmon CSV found"
        ((counters_skip++))
        continue
    fi

    csv_name=$(basename "$csv_file")
    dst_dir="$DST_ROOT/$run_name"
    dst_file="$dst_dir/$csv_name"

    # Create destination directory if needed
    mkdir -p "$dst_dir"

    # If destination already exists, verify MD5 and skip copy
    if [ -f "$dst_file" ]; then
        src_md5=$(md5sum "$csv_file" | awk '{print $1}')
        dst_md5=$(md5sum "$dst_file" | awk '{print $1}')
        if [ "$src_md5" = "$dst_md5" ]; then
            log "[EXISTS-OK] $run_name/$csv_name: already present and verified"
            ((counters_exists++))
        else
            log "[EXISTS-MISMATCH] $run_name/$csv_name: destination differs from source — manual review needed"
            ((counters_error++))
        fi
        continue
    fi

    # Copy
    log "[COPY] $run_name/$csv_name ..."
    cp "$csv_file" "$dst_file"

    # Verify
    src_md5=$(md5sum "$csv_file" | awk '{print $1}')
    dst_md5=$(md5sum "$dst_file" | awk '{print $1}')

    if [ "$src_md5" = "$dst_md5" ]; then
        log "[OK] $run_name/$csv_name: copy verified (MD5: $src_md5)"
        ((counters_ok++))
    else
        log "[ERROR] $run_name/$csv_name: MD5 mismatch — removing failed copy"
        rm "$dst_file"
        ((counters_error++))
    fi
done

log "=== Migration complete ==="
log "  Copied & verified : $counters_ok"
log "  Already present   : $counters_exists"
log "  Skipped (no CSV)  : $counters_skip"
log "  Errors            : $counters_error"
