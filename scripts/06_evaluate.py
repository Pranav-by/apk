"""
Script 06: Evaluation
----------------------
- Reads predictions.csv
- Computes accuracy, precision, recall, F1-score
- Generates confusion matrix heatmap
- Breaks down performance per Android version
- Outputs evaluation_report.txt and confusion_matrix.png
"""

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # non-interactive backend (no display needed)
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

BASE_DIR = Path("/media/pranav/HP P900/apks")
OUTPUT_DIR = BASE_DIR / "output"
PRED_CSV = OUTPUT_DIR / "predictions" / "predictions.csv"
REPORT_DIR = OUTPUT_DIR / "reports"

REPORT_TXT = REPORT_DIR / "evaluation_report.txt"
CM_PNG = REPORT_DIR / "confusion_matrix.png"
CM_VERSION_PNG = REPORT_DIR / "confusion_matrix_per_version.png"


def compute_metrics(y_true, y_pred, label="Overall"):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, pos_label="malicious", zero_division=0)
    rec = recall_score(y_true, y_pred, pos_label="malicious", zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label="malicious", zero_division=0)
    return {
        "label": label,
        "total": len(y_true),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
    }


def main():
    print("=" * 60)
    print("Script 06: Evaluation")
    print("=" * 60)

    if not PRED_CSV.exists():
        print(f"[ERROR] Predictions file not found: {PRED_CSV}")
        print("  → Run script 05 first.")
        return

    df = pd.read_csv(PRED_CSV)
    print(f"Loaded {len(df)} predictions.")

    # Filter only valid predictions
    valid = df[df["predicted_label"].isin(["benign", "malicious"])].copy()
    skipped = len(df) - len(valid)
    if skipped:
        print(f"  [WARNING] Skipped {skipped} rows with invalid/unknown predictions.")

    if len(valid) == 0:
        print("[ERROR] No valid predictions to evaluate.")
        return

    y_true = valid["true_label"].str.lower()
    y_pred = valid["predicted_label"].str.lower()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    lines = []

    # ── Overall Metrics ──────────────────────────────────────────
    overall = compute_metrics(y_true, y_pred, "Overall")
    lines.append("=" * 60)
    lines.append("OVERALL EVALUATION RESULTS")
    lines.append("=" * 60)
    lines.append(f"  Total APKs evaluated : {overall['total']}")
    lines.append(f"  Accuracy             : {overall['accuracy']:.4f}  ({overall['accuracy']*100:.2f}%)")
    lines.append(f"  Precision (malicious): {overall['precision']:.4f}")
    lines.append(f"  Recall    (malicious): {overall['recall']:.4f}")
    lines.append(f"  F1-Score  (malicious): {overall['f1_score']:.4f}")
    lines.append("")
    lines.append("Full Classification Report:")
    lines.append(classification_report(y_true, y_pred, target_names=["benign", "malicious"]))

    # ── Per Android Version ──────────────────────────────────────
    lines.append("=" * 60)
    lines.append("PER ANDROID VERSION BREAKDOWN")
    lines.append("=" * 60)
    per_version = []
    for version in sorted(valid["android_version"].unique()):
        subset = valid[valid["android_version"] == version]
        yt = subset["true_label"].str.lower()
        yp = subset["predicted_label"].str.lower()
        m = compute_metrics(yt, yp, version)
        per_version.append(m)
        lines.append(
            f"  {version:<12} | n={m['total']:>4} | "
            f"Acc={m['accuracy']:.3f} | "
            f"Prec={m['precision']:.3f} | "
            f"Rec={m['recall']:.3f} | "
            f"F1={m['f1_score']:.3f}"
        )

    lines.append("")

    # ── Label Distribution ───────────────────────────────────────
    lines.append("=" * 60)
    lines.append("LABEL DISTRIBUTION")
    lines.append("=" * 60)
    true_dist = y_true.value_counts().to_string()
    pred_dist = y_pred.value_counts().to_string()
    lines.append(f"  True labels:\n{true_dist}")
    lines.append(f"\n  Predicted labels:\n{pred_dist}")
    lines.append("")

    report_text = "\n".join(lines)
    print("\n" + report_text)

    with open(REPORT_TXT, "w") as f:
        f.write(report_text)
    print(f"\n[SAVED] Report: {REPORT_TXT}")

    # ── Confusion Matrix (Overall) ───────────────────────────────
    cm = confusion_matrix(y_true, y_pred, labels=["benign", "malicious"])
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["benign", "malicious"],
        yticklabels=["benign", "malicious"],
        ax=ax
    )
    ax.set_xlabel("Predicted Label", fontsize=12)
    ax.set_ylabel("True Label", fontsize=12)
    ax.set_title(f"Confusion Matrix (n={len(valid)})\nAcc={overall['accuracy']:.3f}  F1={overall['f1_score']:.3f}", fontsize=13)
    plt.tight_layout()
    plt.savefig(CM_PNG, dpi=150)
    plt.close()
    print(f"[SAVED] Confusion matrix: {CM_PNG}")

    # ── Per-Version Accuracy Bar Chart ───────────────────────────
    if per_version:
        vdf = pd.DataFrame(per_version)
        fig, axes = plt.subplots(1, 4, figsize=(16, 5))
        metrics = ["accuracy", "precision", "recall", "f1_score"]
        titles = ["Accuracy", "Precision", "Recall", "F1-Score"]
        colors = ["steelblue", "darkorange", "green", "crimson"]
        for ax, metric, title, color in zip(axes, metrics, titles, colors):
            bars = ax.bar(vdf["label"], vdf[metric], color=color, alpha=0.8)
            ax.set_ylim(0, 1.05)
            ax.set_title(title, fontsize=12, fontweight="bold")
            ax.set_xlabel("Android Version", fontsize=9)
            ax.tick_params(axis="x", rotation=30)
            ax.axhline(0.8, color="red", linestyle="--", linewidth=0.8, label="0.8 threshold")
            for bar, val in zip(bars, vdf[metric]):
                ax.text(bar.get_x() + bar.get_width() / 2, val + 0.01, f"{val:.2f}",
                        ha="center", va="bottom", fontsize=8)
        plt.suptitle("Per Android Version Performance", fontsize=14, fontweight="bold")
        plt.tight_layout()
        plt.savefig(CM_VERSION_PNG, dpi=150)
        plt.close()
        print(f"[SAVED] Per-version chart: {CM_VERSION_PNG}")

    print("\n[DONE] Evaluation complete.")


if __name__ == "__main__":
    main()

