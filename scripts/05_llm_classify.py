"""
Script 05: LLM Classification — LOCAL INFERENCE via llama-cpp-python
----------------------------------------------------------------------
Model  : meta-llama/Llama-3.3-70B-Instruct  (GGUF Q4_K_M quantized)
Backend: llama-cpp-python  (CPU-only, mmap from SSD)
Storage: ~40 GB on your SSD (/media/pranav/HP P900 — 876 GB free ✅)
RAM    : Uses mmap — model lives on SSD, only active layers paged into RAM

Why 70B instead of 8B?
  - 9× more parameters = far superior reasoning
  - Better at understanding complex permission combinations & malware patterns
  - mmap lets it run even without fitting fully in RAM (reads from fast SSD)
  - No API key needed, fully local & offline after download

How it works:
  1. Downloads Llama-3.3-70B Q4_K_M (~40 GB) once to your SSD
  2. Uses mmap: model stays on SSD, RAM holds only active context
  3. Runs inference locally on your i5 CPU (all 8 threads)
  4. Saves predictions incrementally every 10 APKs

Input : output/structured_texts/<sha256>.txt
Output: output/predictions/predictions.csv
"""

import os
import re
import csv
import time
import traceback
from pathlib import Path

import pandas as pd
from tqdm import tqdm

BASE_DIR  = Path("/media/pranav/HP P900/apks")
OUTPUT_DIR = BASE_DIR / "output"
CLEAN_CSV  = OUTPUT_DIR / "features" / "combined_features_clean.csv"
TEXT_DIR   = OUTPUT_DIR / "structured_texts"
PRED_CSV   = OUTPUT_DIR / "predictions" / "predictions.csv"
LOG_FILE   = OUTPUT_DIR / "logs" / "llm_errors.log"
MODEL_DIR  = OUTPUT_DIR / "models"

# ── Model config ──────────────────────────────────────────────────────────────
# Llama-3.1-8B-Instruct Q4_K_M (~4.9 GB on SSD)
# Highly accurate for classification, optimized for 8-core CPU inference
MODEL_REPO = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF"
MODEL_FILE = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"

PRED_FIELDNAMES = ["sha256", "android_version", "true_label",
                   "predicted_label", "confidence", "explanation"]

SYSTEM_PROMPT = """You are an expert Android malware analyst. You will be given a structured static analysis report of an Android APK.

Your task is to classify the APK as either benign or malicious based solely on the provided static features.

Analyze the permissions, components, API calls, network indicators, and other features carefully.

Respond in this EXACT format (no extra text):
PREDICTION: <benign or malicious>
CONFIDENCE: <high, medium, or low>
EXPLANATION: <2-3 sentences explaining the key indicators>"""


def download_model() -> Path:
    """Ensure Llama-3.1-8B GGUF model is present on SSD."""
    from huggingface_hub import hf_hub_download
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / MODEL_FILE

    if model_path.exists():
        size_gb = model_path.stat().st_size / 1e9
        print(f"[MODEL] Model ready on SSD: {model_path.name} ({size_gb:.2f} GB)")
        return model_path

    print(f"\n[MODEL] Downloading {MODEL_FILE} from {MODEL_REPO} ...")
    downloaded = hf_hub_download(
        repo_id=MODEL_REPO,
        filename=MODEL_FILE,
        local_dir=str(MODEL_DIR),
        local_dir_use_symlinks=False,
    )
    print(f"[MODEL] ✅ Downloaded: {downloaded}")
    return Path(downloaded)


def load_model(model_path: Path):
    """Load GGUF model with llama-cpp-python optimized for i5 CPU."""
    from llama_cpp import Llama

    size_gb = model_path.stat().st_size / 1e9
    print(f"\n[MODEL] Loading {model_path.name} ({size_gb:.2f} GB) ...")

    llm = Llama(
        model_path=str(model_path),
        n_ctx=2048,
        n_threads=8,
        n_gpu_layers=0,
        verbose=False,
        chat_format="llama-3",
    )
    print(f"[MODEL] ✅ Loaded successfully!\n")
    return llm


def parse_response(text: str):
    """Extract prediction, confidence, explanation from model output."""
    prediction = "unknown"
    confidence = "unknown"
    explanation = ""

    m = re.search(r"PREDICTION\s*:\s*(benign|malicious)", text, re.IGNORECASE)
    if m:
        prediction = m.group(1).lower()

    m = re.search(r"CONFIDENCE\s*:\s*(high|medium|low)", text, re.IGNORECASE)
    if m:
        confidence = m.group(1).lower()

    m = re.search(r"EXPLANATION\s*:\s*(.+?)(?=\n[A-Z]+:|$)", text, re.IGNORECASE | re.DOTALL)
    if m:
        explanation = m.group(1).strip().replace("\n", " ")[:500]

    return prediction, confidence, explanation


def log_error(sha256: str, error: str):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] SHA256={sha256}\n  {error}\n\n")


def main():
    print("=" * 60)
    print("Script 05: LLM Classification  (LOCAL / OFFLINE)")
    print("  Model  : Llama-3.3-70B-Instruct Q4_K_M (GGUF)")
    print("  Storage: ~40 GB on SSD  (876 GB free ✅)")
    print("  RAM    : mmap — SSD paging, no full RAM load needed")
    print("  Backend: llama-cpp-python (CPU, 8 threads)")
    print("=" * 60)

    if not CLEAN_CSV.exists():
        print(f"[ERROR] {CLEAN_CSV} not found → run script 03 first.")
        return

    df = pd.read_csv(CLEAN_CSV, low_memory=False)
    label_map   = dict(zip(df["sha256"].str.upper(), df["label"]))
    version_map = dict(zip(df["sha256"].str.upper(), df["android_version"]))

    # Resume support
    already_done = set()
    PRED_CSV.parent.mkdir(parents=True, exist_ok=True)
    write_header = not PRED_CSV.exists()
    if PRED_CSV.exists():
        existing = pd.read_csv(PRED_CSV)
        already_done = set(existing["sha256"].str.upper().tolist())
        print(f"Resuming: {len(already_done)} already predicted.")

    text_files = sorted(TEXT_DIR.glob("*.txt"))
    todo = [f for f in text_files if f.stem.upper() not in already_done]
    print(f"Text files: {len(text_files)} | Remaining: {len(todo)}")

    if not todo:
        print("[DONE] All APKs already classified.")
        return

    # Download + load model
    model_path = download_model()
    llm = load_model(model_path)

    pred_file = open(PRED_CSV, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(pred_file, fieldnames=PRED_FIELDNAMES)
    if write_header:
        writer.writeheader()

    errors = 0
    success = 0

    for i, txt_file in enumerate(tqdm(todo, desc="Classifying APKs")):
        sha256 = txt_file.stem.upper()
        true_label      = label_map.get(sha256, "unknown")
        android_version = version_map.get(sha256, "unknown")

        try:
            with open(txt_file, "r", encoding="utf-8") as f:
                apk_report = f.read()

            response = llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": f"Analyze this APK report:\n\n{apk_report}"},
                ],
                max_tokens=90,
                temperature=0.1,
                stop=["</s>", "<|eot_id|>", "<|end_of_text|>", "\n\n\n"],
            )
            response_text = response["choices"][0]["message"]["content"]
            predicted_label, confidence, explanation = parse_response(response_text)

            writer.writerow({
                "sha256": sha256,
                "android_version": android_version,
                "true_label": true_label,
                "predicted_label": predicted_label,
                "confidence": confidence,
                "explanation": explanation,
            })
            pred_file.flush()
            success += 1

        except Exception as e:
            log_error(sha256, traceback.format_exc())
            errors += 1

        if (i + 1) % 10 == 0:
            pred_file.flush()
            tqdm.write(f"  ✓ {i+1}/{len(todo)} | errors: {errors}")

    pred_file.close()
    print(f"\n[DONE] Success: {success} | Errors: {errors}")
    print(f"       Predictions → {PRED_CSV}")


if __name__ == "__main__":
    main()
