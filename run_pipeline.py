#!/usr/bin/env python3
"""
run_pipeline.py — Master Pipeline Runner
-----------------------------------------
Run the full pipeline end-to-end:
  python3 run_pipeline.py

Or run a specific step:
  python3 run_pipeline.py --step 2
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent / "scripts"

STEPS = [
    (1, "01_identify_apks.py",   "APK Identification & Deduplication"),
    (2, "02_extract_features.py","Static Feature Extraction (Androguard)"),
    (3, "03_preprocess.py",      "Feature Preprocessing & Validation"),
    (4, "04_generate_text.py",   "Structured Text Generation"),
    (5, "05_llm_classify.py",    "LLM Classification (Llama-3.1-8B-Instruct)"),
    (6, "06_evaluate.py",        "Evaluation & Reporting"),
]


def run_step(step_num: int, script_name: str, description: str):
    script_path = SCRIPTS_DIR / script_name
    print(f"\n{'='*60}")
    print(f"  STEP {step_num}: {description}")
    print(f"{'='*60}")
    start = time.time()
    result = subprocess.run([sys.executable, str(script_path)], check=False)
    elapsed = time.time() - start
    status = "✅ DONE" if result.returncode == 0 else "❌ FAILED"
    print(f"\n  {status} — {elapsed:.1f}s")
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="APK Malware Detection Pipeline")
    parser.add_argument("--step", type=int, choices=range(1, 7),
                        help="Run only a specific step (1-6). Default: run all.")
    parser.add_argument("--from-step", type=int, choices=range(1, 7), default=1,
                        help="Start from a specific step (1-6).")
    args = parser.parse_args()

    print("\n🚀 Android APK Static Analysis & LLM Classification Pipeline")
    print("   Model: fdtn-ai/Foundation-Sec-8B-Instruct (HuggingFace)")
    print("   Dataset: b/ (benign) + m/ (malicious)")
    print()

    steps_to_run = STEPS
    if args.step:
        steps_to_run = [(n, s, d) for n, s, d in STEPS if n == args.step]
    else:
        steps_to_run = [(n, s, d) for n, s, d in STEPS if n >= args.from_step]

    all_ok = True
    for step_num, script_name, description in steps_to_run:
        ok = run_step(step_num, script_name, description)
        if not ok:
            print(f"\n[PIPELINE STOPPED] Step {step_num} failed. Fix the error and re-run.")
            print(f"  Resume from this step: python3 run_pipeline.py --from-step {step_num}")
            all_ok = False
            break

    if all_ok:
        print(f"\n{'='*60}")
        print("  🎉 PIPELINE COMPLETE — Check output/ for results")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

