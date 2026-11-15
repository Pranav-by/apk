"""
Script 02: Static Feature Extraction using Androguard
------------------------------------------------------
- Reads apk_manifest.csv (from script 01)
- Extracts static features per APK using Androguard
- Writes per-APK JSON and combined benign/malicious CSVs
- Skips already-processed APKs (idempotent)
- Logs errors to output/logs/extraction_errors.log
"""

import os
import re
import json
import csv
import hashlib
import traceback
import logging
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

# Silence androguard's very verbose DEBUG/INFO logging
logging.getLogger("androguard").setLevel(logging.ERROR)
import sys
from loguru import logger as _loguru_logger
_loguru_logger.remove()
_loguru_logger.add(sys.stderr, level="ERROR")

import pandas as pd
from androguard.core.apk import APK
from androguard.core.dex import DEX

BASE_DIR = Path("/media/pranav/HP P900/apks")
OUTPUT_DIR = BASE_DIR / "output"
MANIFEST_CSV = OUTPUT_DIR / "apk_manifest.csv"
JSON_DIR = OUTPUT_DIR / "json"
FEATURES_DIR = OUTPUT_DIR / "features"
LOG_FILE = OUTPUT_DIR / "logs" / "extraction_errors.log"

# Sensitive API patterns to flag
SENSITIVE_API_PATTERNS = {
    "sms_send": [
        "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage",
        "Landroid/telephony/SmsManager"
    ],
    "network": [
        "HttpURLConnection", "OkHttpClient", "Socket", "URL.openConnection",
        "Ljava/net/HttpURLConnection", "Ljava/net/Socket", "Lokhttp3/OkHttpClient"
    ],
    "crypto": [
        "Cipher.getInstance", "MessageDigest", "SecretKey",
        "Ljavax/crypto/Cipher", "Ljava/security/MessageDigest"
    ],
    "reflection": [
        "Class.forName", "Method.invoke", "getDeclaredMethod",
        "Ljava/lang/reflect/Method", "Ljava/lang/Class"
    ],
    "telephony": [
        "TelephonyManager", "getDeviceId", "getSubscriberId", "getLine1Number",
        "Landroid/telephony/TelephonyManager"
    ],
    "dynamic_code": [
        "DexClassLoader", "PathClassLoader", "loadDex",
        "Ldalvik/system/DexClassLoader", "Ldalvik/system/PathClassLoader"
    ],
    "native": [
        "System.loadLibrary", "Runtime.exec",
        "Ljava/lang/Runtime", "Ljava/lang/System"
    ],
    "file_system": [
        "FileOutputStream", "FileInputStream", "openFileOutput",
        "Ljava/io/FileOutputStream", "Ljava/io/FileInputStream"
    ],
}

URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>]{4,}', re.IGNORECASE
)
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def log_error(sha256: str, path: str, error: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] SHA256={sha256} PATH={path}\n  ERROR: {error}\n\n")


def extract_features(apk_path: str, sha256: str, label: str, android_version: str) -> dict:
    features = {
        "sha256": sha256,
        "filename": Path(apk_path).name,
        "android_version": android_version,
        "label": label,
        # APK identity
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        # Permissions
        "permissions": [],
        "permission_count": 0,
        # Components
        "activities": [],
        "activity_count": 0,
        "services": [],
        "service_count": 0,
        "receivers": [],
        "receiver_count": 0,
        "providers": [],
        "provider_count": 0,
        # Intents
        "intent_actions": [],
        "intent_categories": [],
        "intent_count": 0,
        # DEX
        "dex_count": 0,
        "class_count": 0,
        "method_count": 0,
        # Certificate
        "cert_fingerprint": None,
        "cert_issuer": None,
        # URLs / IPs
        "urls": [],
        "ip_addresses": [],
        # Sensitive API indicators
        "api_sms_send": 0,
        "api_network": 0,
        "api_crypto": 0,
        "api_reflection": 0,
        "api_telephony": 0,
        "api_dynamic_code": 0,
        "api_native": 0,
        "api_file_system": 0,
    }

    try:
        apk = APK(apk_path)

        features["package_name"] = apk.get_package()
        features["version_name"] = apk.get_androidversion_name()
        features["version_code"] = apk.get_androidversion_code()
        features["min_sdk"] = apk.get_min_sdk_version()
        features["target_sdk"] = apk.get_target_sdk_version()

        # Permissions
        perms = apk.get_permissions() or []
        features["permissions"] = list(perms)
        features["permission_count"] = len(perms)

        # Components
        activities = apk.get_activities() or []
        services = apk.get_services() or []
        receivers = apk.get_receivers() or []
        providers = apk.get_providers() or []
        features["activities"] = list(activities)
        features["activity_count"] = len(activities)
        features["services"] = list(services)
        features["service_count"] = len(services)
        features["receivers"] = list(receivers)
        features["receiver_count"] = len(receivers)
        features["providers"] = list(providers)
        features["provider_count"] = len(providers)

        # Intent filters
        actions, categories = set(), set()
        try:
            for comp_type in ["activity", "service", "receiver"]:
                filters = apk.get_intent_filters(comp_type, None)
                if filters:
                    for comp, data in filters.items():
                        actions.update(data.get("action", []))
                        categories.update(data.get("category", []))
        except Exception:
            pass
        features["intent_actions"] = list(actions)
        features["intent_categories"] = list(categories)
        features["intent_count"] = len(actions) + len(categories)

        # DEX files
        dex_files = apk.get_all_dex()
        features["dex_count"] = len(list(dex_files)) if dex_files else 0

        # Parse DEX for class/method counts and API scanning
        all_strings = []
        total_classes = 0
        total_methods = 0
        api_hits = {k: 0 for k in SENSITIVE_API_PATTERNS}

        try:
            for dex_bytes in apk.get_all_dex():
                d = DEX(dex_bytes)
                classes = list(d.get_classes())
                total_classes += len(classes)
                for cls in classes:
                    methods = list(cls.get_methods())
                    total_methods += len(methods)
                    for method in methods:
                        method_name = method.name or ""
                        class_name = cls.name or ""
                        combined = class_name + method_name
                        # Check against sensitive API patterns
                        for api_key, patterns in SENSITIVE_API_PATTERNS.items():
                            for pat in patterns:
                                if pat in combined:
                                    api_hits[api_key] = 1
                                    break

                # Collect strings for URL/IP scanning
                try:
                    for s in d.get_strings():
                        val = str(s)
                        all_strings.append(val)
                except Exception:
                    pass
        except Exception:
            pass

        features["class_count"] = total_classes
        features["method_count"] = total_methods
        for api_key, hit in api_hits.items():
            features[f"api_{api_key}"] = hit

        # URL and IP extraction from strings
        all_text = " ".join(all_strings[:5000])  # limit for performance
        urls = list(set(URL_PATTERN.findall(all_text)))[:50]
        ips = list(set(IP_PATTERN.findall(all_text)))[:50]
        features["urls"] = urls
        features["ip_addresses"] = ips

        # Certificate info
        try:
            certs = apk.get_certificates_der_v2() or []
            if not certs:
                certs = apk.get_certificates_v1() or []
            if certs:
                from asn1crypto import x509
                cert = x509.Certificate.load(list(certs)[0] if isinstance(list(certs)[0], bytes) else bytes(list(certs)[0]))
                features["cert_issuer"] = str(cert.issuer.human_friendly)
                features["cert_fingerprint"] = cert.sha256_fingerprint
        except Exception:
            pass

    except Exception as e:
        raise RuntimeError(f"Androguard parse failed: {e}") from e

    return features


def features_to_csv_row(f: dict) -> dict:
    """Flatten list fields to pipe-separated strings for CSV storage."""
    row = dict(f)
    list_fields = ["permissions", "activities", "services", "receivers", "providers",
                   "intent_actions", "intent_categories", "urls", "ip_addresses"]
    for field in list_fields:
        row[field] = "|".join(str(x) for x in (f.get(field) or []))
    return row


def main():
    print("=" * 60)
    print("Script 02: Static Feature Extraction")
    print("=" * 60)

    # Load manifest
    if not MANIFEST_CSV.exists():
        print(f"[ERROR] Manifest not found: {MANIFEST_CSV}")
        print("  → Run script 01 first.")
        return

    manifest = pd.read_csv(MANIFEST_CSV)
    print(f"\nLoaded {len(manifest)} APKs from manifest.")

    # Determine which APKs already processed
    already_done = set()
    for label in ["benign", "malicious"]:
        json_subdir = JSON_DIR / label
        json_subdir.mkdir(parents=True, exist_ok=True)
        for jf in json_subdir.glob("*.json"):
            already_done.add(jf.stem.upper())

    todo = manifest[~manifest["sha256"].isin(already_done)]
    print(f"Already processed: {len(already_done)} | Remaining: {len(todo)}")

    benign_csv = FEATURES_DIR / "benign_features.csv"
    malicious_csv = FEATURES_DIR / "malicious_features.csv"
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    # Prepare CSV writers (append mode)
    csv_files = {}
    csv_writers = {}
    for label, csv_path in [("benign", benign_csv), ("malicious", malicious_csv)]:
        write_header = not csv_path.exists()
        fh = open(csv_path, "a", newline="", encoding="utf-8")
        csv_files[label] = fh
        # We'll create writer after knowing fieldnames from first feature dict

    all_fieldnames = None
    writers_initialized = {}

    errors = 0
    success = 0

    for _, row in tqdm(todo.iterrows(), total=len(todo), desc="Extracting features"):
        sha256 = row["sha256"]
        apk_path = row["path"]
        label = row["label"]
        android_version = row["android_version"]

        try:
            features = extract_features(apk_path, sha256, label, android_version)

            # Save JSON
            json_path = JSON_DIR / label / f"{sha256}.json"
            with open(json_path, "w") as jf:
                json.dump(features, jf, indent=2)

            # Save to CSV
            csv_row = features_to_csv_row(features)
            if all_fieldnames is None:
                all_fieldnames = list(csv_row.keys())
            if label not in writers_initialized:
                csv_path = benign_csv if label == "benign" else malicious_csv
                write_header = csv_path.stat().st_size == 0 if csv_path.exists() else True
                w = csv.DictWriter(csv_files[label], fieldnames=all_fieldnames)
                if write_header:
                    w.writeheader()
                csv_writers[label] = w
                writers_initialized[label] = True
            csv_writers[label].writerow(csv_row)
            csv_files[label].flush()

            success += 1

        except Exception as e:
            log_error(sha256, apk_path, traceback.format_exc())
            errors += 1

    for fh in csv_files.values():
        fh.close()

    print(f"\n[DONE] Feature extraction complete.")
    print(f"       Success: {success} | Errors: {errors}")
    print(f"       Benign CSV:    {benign_csv}")
    print(f"       Malicious CSV: {malicious_csv}")
    print(f"       Error log:     {LOG_FILE}")


if __name__ == "__main__":
    main()
