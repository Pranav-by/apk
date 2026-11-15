"""
Script 03: Feature Preprocessing & Validation
----------------------------------------------
- Loads benign_features.csv + malicious_features.csv
- Handles missing values
- Validates labels & detects cross-label SHA256 conflicts
- Outputs combined_features_clean.csv
"""

import pandas as pd
from pathlib import Path

BASE_DIR = Path("/media/pranav/HP P900/apks")
OUTPUT_DIR = BASE_DIR / "output"
FEATURES_DIR = OUTPUT_DIR / "features"

BENIGN_CSV = FEATURES_DIR / "benign_features.csv"
MALICIOUS_CSV = FEATURES_DIR / "malicious_features.csv"
COMBINED_CSV = FEATURES_DIR / "combined_features.csv"
CLEAN_CSV = FEATURES_DIR / "combined_features_clean.csv"

# Numeric columns — fill missing with 0
NUMERIC_COLS = [
    "permission_count", "activity_count", "service_count", "receiver_count",
    "provider_count", "intent_count", "dex_count", "class_count", "method_count",
    "api_sms_send", "api_network", "api_crypto", "api_reflection",
    "api_telephony", "api_dynamic_code", "api_native", "api_file_system",
]

# String columns — fill missing with "unknown"
STRING_COLS = ["package_name", "version_name", "version_code", "min_sdk", "target_sdk",
               "cert_fingerprint", "cert_issuer"]

# List-as-string columns — fill missing with ""
LIST_COLS = ["permissions", "activities", "services", "receivers", "providers",
             "intent_actions", "intent_categories", "urls", "ip_addresses"]


def main():
    print("=" * 60)
    print("Script 03: Feature Preprocessing")
    print("=" * 60)

    # Load both CSVs
    dfs = []
    for csv_path, expected_label in [(BENIGN_CSV, "benign"), (MALICIOUS_CSV, "malicious")]:
        if csv_path.exists():
            df = pd.read_csv(csv_path, low_memory=False)
            print(f"  Loaded {len(df)} rows from {csv_path.name}")
            dfs.append(df)
        else:
            print(f"  [WARNING] Not found: {csv_path}")

    if not dfs:
        print("[ERROR] No feature CSVs found. Run script 02 first.")
        return

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\nCombined total: {len(combined)} rows")

    # Save raw combined
    combined.to_csv(COMBINED_CSV, index=False)
    print(f"Raw combined saved: {COMBINED_CSV}")

    # ── Validation ──────────────────────────────────────────────
    # Check for cross-label duplicates
    dup_sha = combined.groupby("sha256")["label"].nunique()
    conflicts = dup_sha[dup_sha > 1]
    if len(conflicts):
        print(f"\n[WARNING] {len(conflicts)} SHA256(s) appear with multiple labels — removing:")
        print(conflicts)
        combined = combined[~combined["sha256"].isin(conflicts.index)]
    else:
        print("[OK] No cross-label SHA256 conflicts.")

    # ── Fill Missing Values ──────────────────────────────────────
    for col in NUMERIC_COLS:
        if col in combined.columns:
            combined[col] = pd.to_numeric(combined[col], errors="coerce").fillna(0).astype(int)

    for col in STRING_COLS:
        if col in combined.columns:
            combined[col] = combined[col].fillna("unknown")

    for col in LIST_COLS:
        if col in combined.columns:
            combined[col] = combined[col].fillna("")

    # ── Standardize SDK ─────────────────────────────────────────
    for sdk_col in ["min_sdk", "target_sdk"]:
        if sdk_col in combined.columns:
            combined[sdk_col] = pd.to_numeric(combined[sdk_col], errors="coerce").fillna(0).astype(int)

    # ── Summary ─────────────────────────────────────────────────
    print(f"\nLabel distribution:\n{combined['label'].value_counts().to_string()}")
    print(f"\nAndroid version distribution:\n{combined['android_version'].value_counts().to_string()}")
    print(f"\nMissing values per column (top 10):")
    missing = combined.isnull().sum().sort_values(ascending=False).head(10)
    print(missing.to_string())

    # Save clean CSV
    combined.to_csv(CLEAN_CSV, index=False)
    print(f"\n[DONE] Clean features saved: {CLEAN_CSV}")
    print(f"       Total rows: {len(combined)}")


if __name__ == "__main__":
    main()

