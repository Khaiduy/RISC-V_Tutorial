#!/usr/bin/env python3
"""
OSCORE payload sweep figure for IEEE journal paper.

Produces a column-width PDF suitable for direct \includegraphics{} in LaTeX.
Run: python3 plot_oscore_sweep.py
Output: oscore_sweep.pdf
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# ---------------------------------------------------------------------------
# Data  (Rocket RV32 @ 50 MHz, TinyCrypt, N=100)
# ---------------------------------------------------------------------------
payload      = [10, 20, 50, 100, 200, 500, 1000]
enc_mcycles  = [0.127, 0.161, 0.230, 0.333, 0.541, 1.196, 2.265]  # coap2oscore
dec_mcycles  = [0.144, 0.180, 0.254, 0.364, 0.585, 1.284, 2.424]  # oscore2coap

# ---------------------------------------------------------------------------
# Style — IEEE single-column, black/white, serif
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.family":       "serif",
    "font.size":         8,
    "axes.labelsize":    8,
    "xtick.labelsize":   7,
    "ytick.labelsize":   7,
    "legend.fontsize":   7,
    "lines.linewidth":   1.2,
    "lines.markersize":  4,
    "grid.linewidth":    0.4,
    "grid.color":        "0.7",
    "axes.linewidth":    0.6,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "pdf.fonttype":      42,   # embed fonts (IEEE requirement)
    "ps.fonttype":       42,
})

fig, ax = plt.subplots(figsize=(3.5, 2.6))

# ---------------------------------------------------------------------------
# Lines
# ---------------------------------------------------------------------------
ax.plot(payload, enc_mcycles,
        color="#2166ac", linestyle="-",  marker="s",
        label="coap2oscore()")

ax.plot(payload, dec_mcycles,
        color="#d6604d", linestyle="--", marker="o",
        label="oscore2coap()")

# ---------------------------------------------------------------------------
# X: log scale (payload sizes span 2 decades — log shows all points clearly)
# Y: linear from 0 (shows absolute magnitude directly)
# ---------------------------------------------------------------------------
ax.set_xscale("log")

ax.set_xlim(8, 1400)
ax.set_ylim(0, 3.0)

ax.set_xticks(payload)
ax.get_xaxis().set_major_formatter(ticker.ScalarFormatter())
ax.set_yticks([0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0])

ax.set_xlabel("Application payload (bytes)")
ax.set_ylabel("Execution (Mcycles)")

ax.grid(True, which="major", linewidth=0.4, color="0.75")

ax.legend(loc="upper left", framealpha=0.9, edgecolor="0.6")

fig.tight_layout(pad=0.4)
fig.savefig("oscore_sweep.pdf", bbox_inches="tight")
print("Saved oscore_sweep.pdf")
