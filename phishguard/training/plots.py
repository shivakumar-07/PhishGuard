"""Shared matplotlib helpers for training-result figures.

Styling follows a validated chart palette (categorical slot order:
blue, orange, aqua, yellow, magenta) on a light surface, with recessive
grid/axes and ink-colored text.
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "font.family": "sans-serif",
    "text.color": INK,
    "axes.labelcolor": INK_2,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.edgecolor": BASELINE,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "font.size": 10,
})


def _finish(fig, path, title):
    fig.suptitle(title, fontsize=13, fontweight="bold", color=INK, x=0.02, ha="left")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(path, dpi=160)
    plt.close(fig)
    print(f"      plot -> {path}")


def plot_model_comparison(metrics: list[dict], title: str, path) -> None:
    names = [m["model"].replace("_", " ") for m in metrics]
    keys = ["accuracy", "precision", "recall", "f1"]
    x = np.arange(len(names))
    width = 0.2
    fig, ax = plt.subplots(figsize=(9, 4.4))
    for i, k in enumerate(keys):
        vals = [m[k] for m in metrics]
        bars = ax.bar(x + (i - 1.5) * width, vals, width * 0.92,
                      label=k.capitalize(), color=SERIES[i], zorder=3)
        if k == "f1":  # selective direct labels: one series only
            for b, v in zip(bars, vals):
                ax.annotate(f"{v:.3f}", (b.get_x() + b.get_width() / 2, v),
                            ha="center", va="bottom", fontsize=7.5, color=INK_2)
    ax.set_xticks(x, names)
    ax.set_ylim(0.9, 1.004)
    ax.set_ylabel("Score (test set)")
    ax.set_axisbelow(True)
    ax.legend(ncols=4, frameon=False, loc="lower right", fontsize=9)
    _finish(fig, path, title)


def plot_roc_curves(roc_points: dict, y_test, title: str, path) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 5.2))
    for i, (name, pts) in enumerate(roc_points.items()):
        lw = 2.6 if name == "hybrid_ensemble" else 1.6
        ax.plot(pts["fpr"], pts["tpr"], label=name.replace("_", " "),
                color=SERIES[i % len(SERIES)], linewidth=lw, zorder=3)
    ax.plot([0, 1], [0, 1], "--", color=MUTED, linewidth=1, zorder=2)
    ax.set_xlabel("False-positive rate")
    ax.set_ylabel("True-positive rate")
    ax.set_xlim(-0.002, 0.25)
    ax.set_ylim(0.75, 1.002)
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    _finish(fig, path, title + " (zoomed to top-left)")


def plot_confusion(cm: list, labels: list[str], title: str, path) -> None:
    cm = np.asarray(cm)
    fig, ax = plt.subplots(figsize=(5.4, 4.6))
    ax.grid(False)
    # sequential single-hue ramp (blue)
    ax.imshow(cm, cmap=matplotlib.colors.LinearSegmentedColormap.from_list(
        "pg_blue", ["#cde2fb", "#0d366b"]), alpha=0.95)
    for (i, j), v in np.ndenumerate(cm):
        frac = v / cm.max()
        ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=13,
                fontweight="bold", color="#ffffff" if frac > 0.5 else INK)
    ax.set_xticks(range(len(labels)), [f"Pred: {l}" for l in labels])
    ax.set_yticks(range(len(labels)), [f"True: {l}" for l in labels])
    _finish(fig, path, title)


def plot_feature_importance(importances, title: str, path) -> None:
    feats = [f for f, _ in importances][::-1]
    vals = [v for _, v in importances][::-1]
    fig, ax = plt.subplots(figsize=(7.4, 5.6))
    ax.barh(feats, vals, color=SERIES[0], height=0.62, zorder=3)
    ax.set_axisbelow(True)
    ax.set_xlabel("Gini importance")
    for y, v in enumerate(vals):
        ax.annotate(f" {v:.3f}", (v, y), va="center", fontsize=8, color=INK_2)
    _finish(fig, path, title)
