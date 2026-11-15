#!/usr/bin/env python3
"""
download_model.py — Standalone background downloader for Llama-3.3-70B GGUF
----------------------------------------------------------------------------
Downloads Llama-3.3-70B-Instruct-Q4_K_M.gguf (~40 GB) to the external SSD:
  /media/pranav/HP P900/apks/output/models/
"""

import sys
import time
from pathlib import Path
from huggingface_hub import hf_hub_download

MODEL_REPO = "bartowski/Llama-3.3-70B-Instruct-GGUF"
MODEL_FILE = "Llama-3.3-70B-Instruct-Q4_K_M.gguf"
OUTPUT_DIR = Path("/media/pranav/HP P900/apks/output")
MODEL_DIR  = OUTPUT_DIR / "models"
TARGET_FILE = MODEL_DIR / MODEL_FILE

def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    if TARGET_FILE.exists():
        size_gb = TARGET_FILE.stat().st_size / 1e9
        print(f"[MODEL] Already present on SSD: {TARGET_FILE} ({size_gb:.2f} GB)")
        return

    print("=" * 60)
    print("Downloading Llama-3.3-70B-Instruct Q4_K_M (~40 GB)")
    print(f"Repository : {MODEL_REPO}")
    print(f"Target dir : {MODEL_DIR}")
    print("=" * 60)

    start_time = time.time()
    try:
        downloaded = hf_hub_download(
            repo_id=MODEL_REPO,
            filename=MODEL_FILE,
            local_dir=str(MODEL_DIR),
            local_dir_use_symlinks=False,
        )
        elapsed = time.time() - start_time
        size_gb = Path(downloaded).stat().st_size / 1e9
        print(f"\n[DONE] Successfully downloaded {MODEL_FILE} ({size_gb:.2f} GB) in {elapsed/60:.1f} mins.")
    except Exception as e:
        print(f"\n[ERROR] Download failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

