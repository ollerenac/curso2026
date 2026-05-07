#!/usr/bin/env python3
"""
Remove \\?\ Path Prefix Duplicates from Violation Files

This script normalizes Windows paths by removing the \\?\ prefix and keeping
only unique (ProcessGuid, normalized_image) combinations.

Usage:
    python normalize_path_duplicates.py processguid_image_violations_run01.csv
"""

import pandas as pd
import sys
from pathlib import Path


def normalize_windows_path(path):
    """
    Normalize Windows path by removing \\?\ prefix.
    Keeps original case to preserve the actual Image name from Sysmon.
    """
    if pd.isna(path):
        return path

    path = str(path)

    # Remove \\?\ prefix if present
    if path.startswith('\\\\?\\'):
        return path[4:]

    return path


def remove_path_duplicates(input_file):
    """
    Remove duplicate rows where only difference is \\?\ prefix.

    Strategy:
    1. For each ProcessGuid, normalize all Image paths
    2. Keep only one row per unique (ProcessGuid, normalized_Image) combination
    3. Prefer the version WITHOUT \\?\ prefix (cleaner)
    """

    print(f"Loading: {input_file}")
    df = pd.read_csv(input_file)

    original_count = len(df)
    unique_guids_before = df['ProcessGuid'].nunique()

    print(f"  Original rows: {original_count:,}")
    print(f"  Unique ProcessGuids: {unique_guids_before:,}")

    # Add normalized path column
    df['_normalized_image'] = df['Image'].apply(normalize_windows_path)

    # For case-insensitive comparison (same as find_processguid_image_violations.py)
    df['_normalized_image_lower'] = df['_normalized_image'].apply(
        lambda x: x.lower() if pd.notna(x) else ''
    )

    # Keep unique (ProcessGuid, _normalized_image_lower) combinations
    # When duplicates exist, prefer rows WITHOUT \\?\ prefix
    df['_has_prefix'] = df['Image'].apply(
        lambda x: 1 if (pd.notna(x) and str(x).startswith('\\\\?\\')) else 0
    )

    # Sort by _has_prefix (0 first = prefer non-prefixed paths)
    df_sorted = df.sort_values('_has_prefix')

    # Drop duplicates, keeping first occurrence (non-prefixed path preferred)
    df_clean = df_sorted.drop_duplicates(
        subset=['ProcessGuid', '_normalized_image_lower'],
        keep='first'
    )

    # Update Image column to use normalized path (without \\?\)
    df_clean['Image'] = df_clean['_normalized_image']

    # Remove temporary columns
    df_clean = df_clean.drop(columns=['_normalized_image', '_normalized_image_lower', '_has_prefix'])

    # Sort by ProcessGuid, Image
    df_clean = df_clean.sort_values(['ProcessGuid', 'Image'])

    final_count = len(df_clean)
    unique_guids_after = df_clean['ProcessGuid'].nunique()
    removed = original_count - final_count

    print(f"\n  After normalization:")
    print(f"    Rows: {final_count:,} (removed {removed:,} duplicates)")
    print(f"    Unique ProcessGuids: {unique_guids_after:,}")

    # Create output filename
    input_path = Path(input_file)
    output_file = input_path.parent / f"{input_path.stem}_normalized.csv"

    # Save cleaned version
    df_clean.to_csv(output_file, index=False)
    print(f"\n  Saved to: {output_file}")

    # Show sample of removed duplicates (if any)
    if removed > 0:
        print(f"\n  Sample of normalized paths:")
        # Find some examples where normalization occurred
        df['_norm'] = df['Image'].apply(normalize_windows_path)
        changed = df[df['Image'] != df['_norm']].head(5)
        if len(changed) > 0:
            print("\n  Before → After:")
            for _, row in changed.iterrows():
                print(f"    {row['Image']}")
                print(f"    → {row['_norm']}")
                print()

    return output_file


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python normalize_path_duplicates.py <violation_file.csv>")
        print("\nExample:")
        print("  python normalize_path_duplicates.py processguid_image_violations_run01.csv")
        sys.exit(1)

    input_file = sys.argv[1]

    if not Path(input_file).exists():
        print(f"❌ File not found: {input_file}")
        sys.exit(1)

    print("="*70)
    print("Remove \\\\?\\ Path Prefix Duplicates")
    print("="*70)
    print()

    output_file = remove_path_duplicates(input_file)

    print()
    print("="*70)
    print("✅ Done!")
    print("="*70)
    print()
    print(f"Use the normalized file for investigation:")
    print(f"  {output_file}")
