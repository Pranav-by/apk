"""
Script 04: Structured Text Generation
--------------------------------------
- Reads combined_features_clean.csv
- Converts each APK's features into a structured text prompt
- Saves one .txt file per APK in output/structured_texts/
- Skips already-generated files (idempotent)
"""

import ast
import pandas as pd
from pathlib import Path
from tqdm import tqdm

BASE_DIR = Path("/media/pranav/HP P900/apks")
OUTPUT_DIR = BASE_DIR / "output"
CLEAN_CSV = OUTPUT_DIR / "features" / "combined_features_clean.csv"
TEXT_DIR = OUTPUT_DIR / "structured_texts"


def pipe_to_list(value, limit=20):
    """Convert pipe-separated string back to a list."""
    if pd.isna(value) or value == "":
        return []
    items = [x.strip() for x in str(value).split("|") if x.strip()]
    return items[:limit]


def format_apk_text(row: pd.Series, include_label: bool = False) -> str:
    """Build the structured text prompt for one APK."""
    perms = pipe_to_list(row.get("permissions", ""))
    activities = pipe_to_list(row.get("activities", ""))
    services = pipe_to_list(row.get("services", ""))
    receivers = pipe_to_list(row.get("receivers", ""))
    providers = pipe_to_list(row.get("providers", ""))
    intent_actions = pipe_to_list(row.get("intent_actions", ""))
    urls = pipe_to_list(row.get("urls", ""), limit=10)
    ips = pipe_to_list(row.get("ip_addresses", ""), limit=10)

    def fmt_list(lst, empty="none"):
        return ", ".join(lst) if lst else empty

    def flag(val):
        return "YES" if int(val or 0) else "no"

    text = f"""=== Android APK Static Analysis Report ===

[Identity]
  Package Name  : {row.get('package_name', 'unknown')}
  SHA-256       : {row.get('sha256', 'unknown')}
  Android Group : {row.get('android_version', 'unknown')}
  Version       : {row.get('version_name', 'unknown')} (code: {row.get('version_code', 'unknown')})

[SDK Information]
  Minimum SDK   : {row.get('min_sdk', 'unknown')}
  Target SDK    : {row.get('target_sdk', 'unknown')}

[Permissions ({row.get('permission_count', 0)})]
  {fmt_list(perms)}

[Application Components]
  Activities ({row.get('activity_count', 0)}): {fmt_list(activities)}
  Services   ({row.get('service_count', 0)}): {fmt_list(services)}
  Receivers  ({row.get('receiver_count', 0)}): {fmt_list(receivers)}
  Providers  ({row.get('provider_count', 0)}): {fmt_list(providers)}

[Intent Filters]
  Actions: {fmt_list(intent_actions)}

[DEX Analysis]
  DEX Files     : {row.get('dex_count', 0)}
  Total Classes : {row.get('class_count', 0)}
  Total Methods : {row.get('method_count', 0)}

[Sensitive API Indicators]
  SMS Send          : {flag(row.get('api_sms_send', 0))}
  Network Access    : {flag(row.get('api_network', 0))}
  Cryptography      : {flag(row.get('api_crypto', 0))}
  Java Reflection   : {flag(row.get('api_reflection', 0))}
  Telephony Access  : {flag(row.get('api_telephony', 0))}
  Dynamic Code Load : {flag(row.get('api_dynamic_code', 0))}
  Native Code       : {flag(row.get('api_native', 0))}
  File System Ops   : {flag(row.get('api_file_system', 0))}

[Network Indicators]
  URLs        ({len(urls)}): {fmt_list(urls)}
  IP Addresses({len(ips)}): {fmt_list(ips)}

[Certificate]
  Issuer      : {row.get('cert_issuer', 'unknown')}
  Fingerprint : {row.get('cert_fingerprint', 'unknown')}
"""
    if include_label:
        text += f"\n[Ground Truth Label]: {row.get('label', 'unknown')}\n"

    text += "\n==========================================\n"
    return text


def main():
    print("=" * 60)
    print("Script 04: Structured Text Generation")
    print("=" * 60)

    if not CLEAN_CSV.exists():
        print(f"[ERROR] Clean features CSV not found: {CLEAN_CSV}")
        print("  → Run script 03 first.")
        return

    df = pd.read_csv(CLEAN_CSV, low_memory=False)
    print(f"Loaded {len(df)} APKs from clean features.")

    TEXT_DIR.mkdir(parents=True, exist_ok=True)

    # Skip already generated
    already_done = {f.stem.upper() for f in TEXT_DIR.glob("*.txt")}
    todo = df[~df["sha256"].isin(already_done)]
    print(f"Already generated: {len(already_done)} | Remaining: {len(todo)}")

    for _, row in tqdm(todo.iterrows(), total=len(todo), desc="Generating texts"):
        sha256 = str(row["sha256"]).upper()
        text = format_apk_text(row, include_label=False)  # label hidden for LLM
        out_path = TEXT_DIR / f"{sha256}.txt"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)

    print(f"\n[DONE] Structured texts saved to: {TEXT_DIR}")
    print(f"       Total files: {len(list(TEXT_DIR.glob('*.txt')))}")


if __name__ == "__main__":
    main()

