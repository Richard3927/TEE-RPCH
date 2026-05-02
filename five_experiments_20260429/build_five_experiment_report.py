#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def latex_escape(s: str) -> str:
    if s.startswith("2^") and s[2:].isdigit():
        return f"${s}$"
    return (
        s.replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("%", r"\%")
        .replace("&", r"\&")
        .replace("#", r"\#")
    )


def csv_to_tex(csv_path: Path, tex_path: Path) -> None:
    rows = list(csv.reader(csv_path.read_text(encoding="utf-8").splitlines()))
    header = rows[0]
    body = rows[1:]
    cols = " ".join(["c"] * len(header))
    lines = [r"\begin{tabular}{" + cols + "}", r"\toprule"]
    lines.append(" & ".join(latex_escape(v) for v in header) + r" \\")
    lines.append(r"\midrule")
    for row in body:
        lines.append(" & ".join(latex_escape(v) for v in row) + r" \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    tex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


TEX = r"""
\documentclass[10pt]{article}
\usepackage[margin=0.82in]{geometry}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{multirow}
\usepackage{amsmath}
\usepackage{amssymb}
\usepackage{float}
\usepackage{hyperref}
\usepackage{placeins}
\title{TEE-RPCH Five-Experiment Report}
\author{Real SGX HW measurements}
\date{}

\begin{document}
\maketitle

\section{Experimental Scope}
This report contains only the isolated five-experiment results generated under \texttt{five\_experiments\_20260429}. All TEE-RPCH measurements come from the hardware SGX path with the current implementation tag \texttt{tee-rpch-v9-sgx-2od-split-legacy-reenc}. The split enforced in the measured code is: server-side \texttt{Transform1}, enclave-side membership check, HK decryption, \texttt{Transform2}, and ETD2 checking, then user-side final decryption and hash-based consistency checking.

\section{Experiment 1: Theory Comparison}
\begin{table}[H]
\centering
\caption{Theory-level comparison of representative revocable PCH/RPCH schemes.}
\scriptsize
\resizebox{\textwidth}{!}{\input{../tables/experiment1_theory.tex}}
\end{table}

\section{Experiment 2: Baseline Comparison}
This experiment compares the secure single-outsourcing baseline \texttt{CHET-OA + FAME-OD} against the deployed split design \texttt{CHET-2OA + FAME-2OD + SGX}. The TEE-RPCH end-to-end cost includes the first outsourcing layer, the enclave stage, and the user-side finalization.

\begin{figure}[H]
\centering
\includegraphics[width=0.84\textwidth]{../figures/adapt_comparison.pdf}
\caption{End-to-end adaptation cost versus policy size.}
\end{figure}

\begin{figure}[H]
\centering
\includegraphics[width=0.84\textwidth]{../figures/adapt_breakdown.pdf}
\caption{Server, enclave, and user-side adaptation breakdown.}
\end{figure}

\begin{table}[H]
\centering
\caption{Baseline comparison across policy sizes (ms).}
\scriptsize
\resizebox{\textwidth}{!}{\input{../tables/experiment2_baseline.tex}}
\end{table}

\section{Experiment 3: Hash-Check Benefit}
This experiment isolates the benefit of replacing the old client-side ciphertext-consistency path with the current hash-check path.

\begin{figure}[H]
\centering
\includegraphics[width=0.82\textwidth]{../figures/exp3_hashcheck.pdf}
\caption{Legacy finalize path versus hash-check finalize path.}
\end{figure}

\begin{table}[H]
\centering
\caption{Legacy finalize path versus hash-check path (ms).}
\scriptsize
\resizebox{\textwidth}{!}{\input{../tables/experiment3_usercheck.tex}}
\end{table}

\section{Experiment 4: Multi-thread Evaluation}
\begin{figure}[H]
\centering
\includegraphics[width=0.84\textwidth]{../figures/cost_tasks_threads.pdf}
\caption{Total wall-clock cost versus task count under fixed thread counts.}
\end{figure}

\begin{figure}[H]
\centering
\includegraphics[width=0.84\textwidth]{../figures/cost_threads_policy.pdf}
\caption{Total wall-clock cost versus server thread count under fixed policy sizes.}
\end{figure}

\section{Experiment 5: Revocation Comparison}
This experiment compares the online revocation-related costs of EHR-RPCH, TAR-PCH, and TEE-RPCH. For TEE-RPCH, the online path is split into KGC state signing and enclave-side state checking.

\begin{figure}[H]
\centering
\includegraphics[width=0.84\textwidth]{../figures/revocation_cost.pdf}
\caption{Revocation cost versus the number of users.}
\end{figure}

\begin{table}[H]
\centering
\caption{Revocation comparison (ms).}
\scriptsize
\resizebox{\textwidth}{!}{\input{../tables/experiment5_revocation.tex}}
\end{table}

\FloatBarrier
\end{document}
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()

    root = Path(args.root).resolve()
    tables_dir = root / "tables"
    figures_dir = root / "figures"
    report_dir = root / "report"
    report_dir.mkdir(parents=True, exist_ok=True)

    mapping = {
        "experiment1_theory.csv": "experiment1_theory.tex",
        "experiment2_baseline.csv": "experiment2_baseline.tex",
        "experiment3_usercheck.csv": "experiment3_usercheck.tex",
        "experiment5_revocation.csv": "experiment5_revocation.tex",
    }
    for src, dst in mapping.items():
        csv_to_tex(tables_dir / src, tables_dir / dst)

    tex_path = report_dir / "five_experiments_report.tex"
    tex_path.write_text(TEX.strip() + "\n", encoding="utf-8")

    cmd = ["xelatex", "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=str(report_dir))
    subprocess.run(cmd, check=True, cwd=str(report_dir))
    print(report_dir / "five_experiments_report.pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
