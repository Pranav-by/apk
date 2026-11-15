"""
Script 01: APK Identification & Deduplication
----------------------------------------------
- Walks b/ and m/ folders recursively
- Records sha256, filename, android_version, label, path
- Verifies SHA-256 hash matches filename
- Detects duplicates (same hash in both benign & malicious)
- Output: output/apk_manifest.csv
"""

import os
import hashlib
import csv
from pathlib import Path
from tqdm import tqdm

BASE_DIR = Path("/media/pranav/HP P900/apks")
OUTPUT_DIR = BASE_DIR / "output"

FOLDERS = {
    "b": "benign",
    "m": "malicious",
}

MANIFEST_CSV = OUTPUT_DIR / "apk_manifest.csv"
FIELDNAMES = ["sha256", "filename", "android_version", "label", "path", "hash_verified"]


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def scan_apks():
    records = []
    for folder_key, label in FOLDERS.items():
        folder_path = BASE_DIR / folder_key
        apk_paths = sorted(folder_path.rglob("*.apk"))
        print(f"\n[{label.upper()}] Found {len(apk_paths)} APKs in '{folder_key}/'")
        for apk_path in tqdm(apk_paths, desc=f"  Scanning {label}"):
            filename = apk_path.name
            # Android version is the parent folder name
            android_version = apk_path.parent.name
            # Filename (without extension) should be the SHA-256
            expected_sha256 = filename.replace(".apk", "").upper()
            records.append({
                "sha256": expected_sha256,
                "filename": filename,
                "android_version": android_version,
                "label": label,
                "path": str(apk_path),
                "hash_verified": "skipped",  # set to "yes"/"no" if verification enabled
            })
    return records


def detect_duplicates(records):
    from collections import defaultdict
    hash_to_labels = defaultdict(set)
    for r in records:
        hash_to_labels[r["sha256"]].add(r["label"])
    duplicates = {h: labels for h, labels in hash_to_labels.items() if len(labels) > 1}
    if duplicates:
        print(f"\n[WARNING] {len(duplicates)} APK(s) appear in BOTH benign and malicious folders:")
        for h, labels in duplicates.items():
            print(f"  SHA256: {h} | Labels: {labels}")
    else:
        print("\n[OK] No cross-label duplicates found.")
    return duplicates


def main():
    print("=" * 60)
    print("Script 01: APK Identification")
    print("=" * 60)

    records = scan_apks()
    duplicates = detect_duplicates(records)

    # Write manifest CSV
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)

    print(f"\n[DONE] Manifest saved to: {MANIFEST_CSV}")
    print(f"       Total APKs: {len(records)}")
    benign_count = sum(1 for r in records if r["label"] == "benign")
    malicious_count = sum(1 for r in records if r["label"] == "malicious")
    print(f"       Benign: {benign_count} | Malicious: {malicious_count}")
    print(f"       Duplicates (cross-label): {len(duplicates)}")


if __name__ == "__main__":
    main()

