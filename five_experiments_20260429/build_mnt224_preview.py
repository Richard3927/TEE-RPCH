#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

import matplotlib
from matplotlib import font_manager

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
DATA = ROOT / "data_mnt224"
REV_DATA = ROOT / "targeted_tables" / "raw" / "mnt224"
OUT = ROOT / "preview_mnt224"
FIG = OUT / "figures"
TAB = OUT / "tables"
FONT_DIR = PROJECT_ROOT / "fonts"


def _load_times_font() -> str:
    for path in (
        FONT_DIR / "TimesNewRoman-Regular.ttf",
        FONT_DIR / "TimesNewRoman.ttf",
        FONT_DIR / "Times New Roman.ttf",
    ):
        if path.exists():
            font_manager.fontManager.addfont(str(path))
            return font_manager.FontProperties(fname=str(path)).get_name()
    return "Times New Roman"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


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


def csv_to_latex_table(csv_path: Path, tex_path: Path) -> None:
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


def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(str(x) for x in cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=str(cwd))


def generate_base_figures() -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    missing = ROOT / "__missing_typea_dir__"
    run(
        [
            "python3",
            str(PROJECT_ROOT / "generate_paper_assets.py"),
            "--data-dir",
            str(DATA),
            "--typea-dir",
            str(missing),
            "--out-dir",
            str(FIG),
        ],
        PROJECT_ROOT,
    )


def generate_exp3_figure() -> None:
    policies = [10, 20, 30, 40, 60]
    legacy = []
    hashcheck = []
    verify_legacy = []
    verify_hash = []
    for p in policies:
        t = read_json(DATA / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        legacy.append(float(t["LegacyUserAdapt"]))
        hashcheck.append(float(t["UserAdapt"]))
        verify_legacy.append(float(t["LegacyUserAdapt.Verify"]))
        verify_hash.append(float(t["UserAdapt.Verify"]))

    plt.rcParams.update(
        {
            "font.family": _load_times_font(),
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "mathtext.fontset": "stix",
            "mathtext.rm": "Times New Roman",
            "mathtext.it": "Times New Roman:italic",
            "mathtext.bf": "Times New Roman:bold",
            "font.size": 11,
            "axes.labelsize": 11,
            "axes.titlesize": 11,
            "legend.fontsize": 10,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, axes = plt.subplots(1, 2, figsize=(8.0, 3.4))

    axes[0].plot(policies, legacy, color="#8c564b", marker="s", linewidth=1.8, label="Legacy finalize")
    axes[0].plot(policies, hashcheck, color="#d62728", marker="o", linewidth=1.9, label="Hash-check finalize")
    axes[0].set_xlabel("Policy attributes")
    axes[0].set_ylabel("User finalize cost (ms)")
    axes[0].set_xticks(policies)
    axes[0].grid(True, alpha=0.25)
    axes[0].legend(frameon=False, loc="upper left")

    axes[1].plot(policies, verify_legacy, color="#8c564b", marker="s", linewidth=1.8, label="Legacy verify")
    axes[1].plot(policies, verify_hash, color="#d62728", marker="o", linewidth=1.9, label="Hash-check verify")
    axes[1].set_xlabel("Policy attributes")
    axes[1].set_ylabel("Verify sub-cost (ms)")
    axes[1].set_xticks(policies)
    axes[1].grid(True, alpha=0.25)
    axes[1].legend(frameon=False, loc="upper left")

    fig.tight_layout()
    fig.savefig(FIG / "exp3_hashcheck.pdf", bbox_inches="tight")
    plt.close(fig)


def _available_revocation_users() -> list[int]:
    rev_users = {int(p.stem.split("_")[-1]) for p in REV_DATA.glob("rpch_rev_*.json")}
    state_users = {int(p.stem.split("_")[-1]) for p in REV_DATA.glob("hrpch_state_*.json")}
    return sorted(rev_users & state_users)


def generate_exp5_figure() -> None:
    users = _available_revocation_users()
    x_labels = [f"2^{n.bit_length() - 1}" for n in users]

    ehr_total = []
    tar_total = []
    ehr_kgc = []
    ehr_csp = []
    tar_aa = []
    tar_csp = []
    tee_kgc = []
    tee_check = []
    tee_total = []

    for n in users:
        rp = read_json(REV_DATA / f"rpch_rev_{n}.json")["schemes"]
        hs = read_json(REV_DATA / f"hrpch_state_{n}.json")["times_ms"]
        ehr_kgc.append(float(rp["EHR_RPCH"]["times_ms"]["EtdRevoke.KGC"]))
        ehr_csp.append(float(rp["EHR_RPCH"]["times_ms"]["EtdRevoke.CSP"]))
        ehr_total.append(float(rp["EHR_RPCH"]["times_ms"]["EtdRevoke"]))
        tar_aa.append(float(rp["TAR_PCH"]["times_ms"]["Revocation.KGC"]))
        tar_csp.append(float(rp["TAR_PCH"]["times_ms"]["Revocation.CSP"]))
        tar_total.append(float(rp["TAR_PCH"]["times_ms"]["Revocation"]))
        kgc = float(hs["State.Sign(KGC,revoked)"])
        check = float(hs["State.Check(TEE,revoked)"])
        tee_kgc.append(kgc)
        tee_check.append(check)
        tee_total.append(kgc + check)

    plt.rcParams.update(
        {
            "font.family": _load_times_font(),
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "mathtext.fontset": "stix",
            "mathtext.rm": "Times New Roman",
            "mathtext.it": "Times New Roman:italic",
            "mathtext.bf": "Times New Roman:bold",
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 10,
            "legend.fontsize": 8.5,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.2))

    ax = axes[0]
    ax.plot(users, ehr_total, marker="s", linewidth=1.7, label="EHR-RPCH")
    ax.plot(users, tar_total, marker="^", linewidth=1.7, label="TAR-PCH")
    ax.plot(users, tee_total, marker="o", linewidth=1.9, label="TEE-RPCH Total")
    ax.plot(users, tee_kgc, marker="D", linewidth=1.4, label="TEE-RPCH KGC")
    ax.plot(users, tee_check, marker="x", linewidth=1.4, label="TEE-RPCH TEE Check")
    ax.set_xlabel("N")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Revocation Cost vs #Users")
    ax.set_xticks(users)
    ax.set_xticklabels(x_labels)
    ax.grid(True, alpha=0.25)
    ax.legend(frameon=False, loc="upper left")

    ax = axes[1]
    ax.plot(users, ehr_kgc, marker="s", linewidth=1.7, label="EHR KGC")
    ax.plot(users, ehr_csp, marker="s", linewidth=1.4, linestyle="--", label="EHR CSP")
    ax.plot(users, tar_aa, marker="^", linewidth=1.7, label="TAR AA")
    ax.plot(users, tar_csp, marker="^", linewidth=1.4, linestyle="--", label="TAR CSP")
    ax.plot(users, tee_kgc, marker="D", linewidth=1.4, label="TEE KGC")
    ax.plot(users, tee_check, marker="x", linewidth=1.4, label="TEE Check")
    ax.plot(users, tee_total, marker="o", linewidth=1.9, label="TEE Total")
    ax.set_xlabel("N")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Role-Split Revocation Cost")
    ax.set_xticks(users)
    ax.set_xticklabels(x_labels)
    ax.grid(True, alpha=0.25)
    ax.yaxis.set_major_formatter(ScalarFormatter(useMathText=False))
    ax.ticklabel_format(style="plain", axis="y")
    ax.legend(frameon=False, loc="upper left", ncol=1)

    fig.tight_layout()
    fig.savefig(FIG / "revocation_cost.pdf", bbox_inches="tight")
    plt.close(fig)


def build_tables() -> None:
    TAB.mkdir(parents=True, exist_ok=True)

    theory_rows = [
        ["FB-PCH", "O(|S|)", "O(|policy|)", "O(|policy|)"],
        ["EHR-RPCH", "O(|S| + log N)", "O(|policy|)", "O(|policy| + outsourced revoke)"],
        ["PNITCH", "O(|S|)", "O(1)", "O(t) partial adapt + combine"],
        ["RPCH-XNM'21", "O(|S| + log N)", "O(|policy|)", "O(|policy| + log N)"],
        ["TAR-PCH", "O(|S| + log N)", "O(|policy|)", "O(|policy| + cloud update)"],
        ["TPCH", "O(|S|)", "O(|policy|)", "O(|policy| + update rounds)"],
        ["TEE-RPCH (ours)", "O(|S|)", "O(|policy|)", "Server O(|policy|), TEE O(log N), User O(1)"],
    ]
    write_csv(TAB / "exp1_theory.csv", ["scheme", "keygen", "hash", "adapt"], theory_rows)

    exp2_rows = []
    for p in [10, 20, 30, 40, 60]:
        t = read_json(DATA / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        e2e = float(t["ServerAdapt"]) + float(t["InsiderAdapt(TEE)"]) + float(t["UserAdapt"])
        exp2_rows.append(
            [
                str(p),
                f"{float(t['BaselineOD.Adapt']):.3f}",
                f"{e2e:.3f}",
                f"{float(t['ServerAdapt']):.3f}",
                f"{float(t['InsiderAdapt(TEE)']):.3f}",
                f"{float(t['UserAdapt']):.3f}",
            ]
        )
    write_csv(
        TAB / "exp2_baseline.csv",
        ["policy", "single_outsource_ms", "tee_rpch_e2e_ms", "server_ms", "tee_ms", "user_ms"],
        exp2_rows,
    )

    exp3_rows = []
    for p in [10, 20, 30, 40, 60]:
        t = read_json(DATA / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        exp3_rows.append(
            [
                str(p),
                f"{float(t['LegacyUserAdapt']):.3f}",
                f"{float(t['UserAdapt']):.3f}",
                f"{float(t['LegacyUserAdapt.Verify']):.3f}",
                f"{float(t['UserAdapt.Verify']):.3f}",
            ]
        )
    write_csv(
        TAB / "exp3_hashcheck.csv",
        ["policy", "legacy_user_ms", "hashcheck_user_ms", "legacy_verify_ms", "hashcheck_verify_ms"],
        exp3_rows,
    )

    exp5_rows = []
    for n in _available_revocation_users():
        exp = n.bit_length() - 1
        hs = read_json(REV_DATA / f"hrpch_state_{n}.json")["times_ms"]
        rp = read_json(REV_DATA / f"rpch_rev_{n}.json")["schemes"]
        kgc = float(hs["State.Sign(KGC,revoked)"])
        tee = float(hs["State.Check(TEE,revoked)"])
        exp5_rows.append(
            [
                f"2^{exp}",
                f"{float(rp['EHR_RPCH']['times_ms']['EtdRevoke.KGC']):.3f}",
                f"{float(rp['EHR_RPCH']['times_ms']['EtdRevoke.CSP']):.3f}",
                f"{float(rp['EHR_RPCH']['times_ms']['EtdRevoke']):.3f}",
                f"{float(rp['TAR_PCH']['times_ms']['Revocation.KGC']):.3f}",
                f"{float(rp['TAR_PCH']['times_ms']['Revocation.CSP']):.3f}",
                f"{float(rp['TAR_PCH']['times_ms']['Revocation']):.3f}",
                f"{kgc:.3f}",
                f"{tee:.3f}",
                f"{kgc + tee:.3f}",
            ]
        )
    write_csv(
        TAB / "exp5_revocation.csv",
        [
            "users",
            "ehr_kgc_ms",
            "ehr_csp_ms",
            "ehr_total_ms",
            "tar_aa_ms",
            "tar_csp_ms",
            "tar_total_ms",
            "tee_kgc_ms",
            "tee_ms",
            "tee_total_ms",
        ],
        exp5_rows,
    )

    for stem in ["exp1_theory", "exp2_baseline", "exp3_hashcheck", "exp5_revocation"]:
        csv_to_latex_table(TAB / f"{stem}.csv", TAB / f"{stem}.tex")


def build_report() -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    tex = OUT / "mnt224_preview_acm.tex"
    pdf = OUT / "mnt224_preview_acm.pdf"
    tex_text = r"""
\PassOptionsToPackage{table}{xcolor}
\documentclass[sigconf]{acmart}
\setcopyright{none}
\settopmatter{printacmref=false}
\renewcommand\footnotetextcopyrightpermission[1]{}

\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{multirow}
\usepackage{tabularx}
\usepackage{amsmath}
\usepackage{float}
\usepackage{hyperref}
\usepackage{placeins}
\usepackage{stfloats}

\setlength{\textfloatsep}{4pt plus 1pt minus 1pt}
\setlength{\floatsep}{4pt plus 1pt minus 1pt}
\setlength{\intextsep}{4pt plus 1pt minus 1pt}
\setlength{\dbltextfloatsep}{4pt plus 1pt minus 1pt}
\setlength{\dblfloatsep}{4pt plus 1pt minus 1pt}
\setlength{\abovecaptionskip}{2pt}
\setlength{\belowcaptionskip}{0pt}
\renewcommand{\topfraction}{0.98}
\renewcommand{\dbltopfraction}{0.98}
\renewcommand{\bottomfraction}{0.9}
\renewcommand{\textfraction}{0.01}
\renewcommand{\floatpagefraction}{0.55}
\renewcommand{\dblfloatpagefraction}{0.55}
\setcounter{topnumber}{4}
\setcounter{bottomnumber}{2}
\setcounter{dbltopnumber}{3}
\setcounter{totalnumber}{6}
\newcommand{\TableStyle}{\setlength{\tabcolsep}{3pt}\renewcommand{\arraystretch}{1.06}}
\newcommand{\TableStyleTight}{\setlength{\tabcolsep}{2.6pt}\renewcommand{\arraystretch}{1.03}}

\title[TEE-RPCH MNT224 Preview]{TEE-RPCH Experimental Preview on MNT224}
\author{Anonymous}
\affiliation{\institution{Anonymous Institution}}
\date{}

\begin{abstract}
This preview document isolates the MNT224 experimental results generated from the completed real-SGX measurements. The preview uses the full \texttt{data\_mnt224} set for baseline, hash-check, and concurrency plots, and the refreshed \texttt{targeted\_tables/raw/mnt224} revocation results for the revocation section.
\end{abstract}

\begin{document}
\maketitle

\section{Experimental Scope}
The preview focuses on the corrected five-experiment structure: a theory-level comparison, a secure baseline comparison, the user-side hash-check benefit, a multi-thread experiment, and a revocation comparison. All TEE-RPCH results in this preview come from the completed MNT224 hardware-SGX run.

\section{Experiment 1: Theory Comparison}
\begin{table*}[t]
\centering
\caption{Theory comparison.}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{tables/exp1_theory.tex}}
\end{table*}

\section{Experiment 2: Baseline Comparison}
\begin{figure*}[t]
\centering
\includegraphics[width=0.82\textwidth]{figures/adapt_comparison.pdf}
\caption{Online adaptation cost versus policy size.}
\end{figure*}
\begin{figure*}[t]
\centering
\includegraphics[width=0.78\textwidth]{figures/adapt_breakdown.pdf}
\caption{Server, enclave, and user breakdown.}
\end{figure*}
\begin{table*}[t]
\centering
\caption{MNT224 baseline comparison (ms).}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{tables/exp2_baseline.tex}}
\end{table*}

\section{Experiment 3: Hash-Check Benefit}
\begin{figure*}[t]
\centering
\includegraphics[width=0.86\textwidth]{figures/exp3_hashcheck.pdf}
\caption{Legacy finalize path versus hash-check path on MNT224.}
\end{figure*}
\begin{table*}[t]
\centering
\caption{MNT224 user-side finalize comparison (ms).}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{tables/exp3_hashcheck.tex}}
\end{table*}

\section{Experiment 4: Multi-thread Evaluation}
\begin{figure*}[t]
\centering
\includegraphics[width=0.82\textwidth]{figures/cost_tasks_threads.pdf}
\caption{Wall-clock cost versus task count.}
\end{figure*}
\begin{figure*}[t]
\centering
\includegraphics[width=0.82\textwidth]{figures/cost_threads_policy.pdf}
\caption{Wall-clock cost versus server thread count.}
\end{figure*}

\section{Experiment 5: Revocation}
\begin{figure*}[t]
\centering
\includegraphics[width=0.75\textwidth]{figures/revocation_cost.pdf}
\caption{Revocation cost versus number of users.}
\end{figure*}
\begin{table*}[t]
\centering
\caption{MNT224 revocation comparison (ms).}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{tables/exp5_revocation.tex}}
\end{table*}

\FloatBarrier
\end{document}
"""
    tex.write_text(tex_text.strip() + "\n", encoding="utf-8")
    run(["xelatex", "-interaction=nonstopmode", "-halt-on-error", tex.name], OUT)
    run(["xelatex", "-interaction=nonstopmode", "-halt-on-error", tex.name], OUT)
    return pdf


def main() -> int:
    generate_base_figures()
    generate_exp3_figure()
    generate_exp5_figure()
    build_tables()
    pdf = build_report()
    print(pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
