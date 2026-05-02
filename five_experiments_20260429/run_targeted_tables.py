#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import matplotlib
from matplotlib import font_manager

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
HRPCH = PROJECT / "hr_pch_sgx"
APP = HRPCH / "app"
RPCH_BENCH = PROJECT / "rpch_bench" / "rpch_bench"
OUT = ROOT / "targeted_tables"
RAW = OUT / "raw"
TABLES = OUT / "tables"
FIGURES = OUT / "figures"
REPORT = OUT / "report"
FONT_DIR = PROJECT / "fonts"

EXPECTED_HRPCH_VERSION = "tee-rpch-v10-sgx-2od-split-full-reenc"
EXPECTED_RPCH_VERSION = "rpch-baselines-v10-ehr-tar-full-revocation-split"
SPLIT_SUM_TOL_MS = 0.5
POLICIES = [10, 20, 30, 40, 60]
REV_USERS_EXP = [10, 12, 14, 16, 18]
CURVES = ["mnt224", "a1"]


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


def memory_used_pct() -> float:
    total = None
    available = None
    with open("/proc/meminfo", "r", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("MemTotal:"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1])
            if total is not None and available is not None:
                break
    if not total or available is None:
        raise RuntimeError("Unable to read memory usage from /proc/meminfo")
    return (total - available) * 100.0 / total


def kill_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        proc.terminate()
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception:
        proc.kill()
    proc.wait(timeout=5)


def run_cmd(cmd: list[str], cwd: Path, max_mem_pct: float, poll_secs: float) -> None:
    mem = memory_used_pct()
    if mem >= max_mem_pct:
        raise RuntimeError(f"Refuse to start command because memory usage is {mem:.2f}% >= {max_mem_pct:.2f}%")
    print(f"+ {' '.join(cmd)}  [mem={mem:.2f}%]", flush=True)
    proc = subprocess.Popen(cmd, cwd=str(cwd), start_new_session=True)
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                if rc != 0:
                    raise subprocess.CalledProcessError(rc, cmd)
                return
            mem = memory_used_pct()
            if mem >= max_mem_pct:
                kill_group(proc)
                raise RuntimeError(f"Aborted command because memory usage reached {mem:.2f}% >= {max_mem_pct:.2f}%")
            time.sleep(poll_secs)
    except BaseException:
        kill_group(proc)
        raise


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fmt(v: float) -> str:
    return f"{float(v):.1f}"


def fmt3(v: float) -> str:
    return f"{float(v):.3f}"


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def latex_escape(s: str) -> str:
    return (
        str(s)
        .replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("%", r"\%")
        .replace("&", r"\&")
        .replace("#", r"\#")
    )


def require_hrpch(path: Path, curve: str) -> None:
    j = read_json(path)
    params = j.get("params", {})
    times = j.get("times_ms", {})
    checks = {
        "curve": params.get("curve") == curve,
        "dlo_version": params.get("dlo_version") == EXPECTED_HRPCH_VERSION,
        "sgx_mode": params.get("sgx_mode") == "HW",
        "tee_hk_decrypt": params.get("tee_hk_decrypt") is True,
        "tee_transform2": params.get("tee_transform2") is True,
        "tee_etd2_check": params.get("tee_etd2_check") is True,
        "user_final_hash_check": params.get("user_final_hash_check") is True,
        "FullReEncUserAdapt": "FullReEncUserAdapt" in times,
    }
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        raise RuntimeError(f"{path} failed HR-PCH validation: {failed}")


def require_state(path: Path, curve: str) -> None:
    j = read_json(path)
    params = j.get("params", {})
    times = j.get("times_ms", {})
    checks = {
        "curve": params.get("curve") == curve,
        "dlo_version": params.get("dlo_version") == EXPECTED_HRPCH_VERSION,
        "sgx_mode": params.get("sgx_mode") == "HW",
        "state_sign": "State.Sign(KGC,revoked)" in times,
        "state_check": "State.Check(TEE,revoked)" in times,
    }
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        raise RuntimeError(f"{path} failed state validation: {failed}")


def require_rpch(path: Path, curve: str) -> None:
    j = read_json(path)
    params = j.get("params", {})
    schemes = j.get("schemes", {})
    checks = {
        "curve": params.get("curve") == curve,
        "bench_version": params.get("bench_version") == EXPECTED_RPCH_VERSION,
        "EHR_RPCH": "EHR_RPCH" in schemes,
        "TAR_PCH": "TAR_PCH" in schemes,
    }
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        raise RuntimeError(f"{path} failed RPCH validation: {failed}")


def require_strict_revocation_baselines(path: Path) -> None:
    j = read_json(path)
    schemes = j.get("schemes", {})
    ehr = schemes.get("EHR_RPCH", {}).get("times_ms", {})
    tar = schemes.get("TAR_PCH", {}).get("times_ms", {})

    issues: list[str] = []

    ehr_kgc = float(ehr.get("EtdRevoke.KGC", 0.0))
    if ehr_kgc <= 0.01:
        issues.append("EHR_RPCH KGC cost is near zero")
    for field in ("EtdRevoke.KGC.KUpt", "EtdRevoke.KGC.DKGen", "EtdRevoke.KGC.Assign"):
        if field not in ehr:
            issues.append(f"EHR_RPCH missing detailed KGC field {field}")
    if all(field in ehr for field in ("EtdRevoke.KGC.KUpt", "EtdRevoke.KGC.DKGen", "EtdRevoke.KGC.Assign")):
        split_sum = sum(float(ehr[field]) for field in ("EtdRevoke.KGC.KUpt", "EtdRevoke.KGC.DKGen", "EtdRevoke.KGC.Assign"))
        if abs(split_sum - ehr_kgc) > SPLIT_SUM_TOL_MS:
            issues.append("EHR_RPCH KGC total does not match KUpt+DKGen+Assign")

    tar_kgc = float(tar.get("Revocation.KGC", 0.0))
    if tar_kgc <= 0.01:
        issues.append("TAR_PCH KGC cost is near zero")
    for field in ("KeySanityCheck.AA", "UserTrace.AA", "KEKUpdate.CSP", "CTUpdate.CSP", "ReHash.CSP"):
        if field not in tar:
            issues.append(f"TAR_PCH missing detailed revocation field {field}")
    if all(field in tar for field in ("KeySanityCheck.AA", "UserTrace.AA")):
        kgc_split = float(tar["KeySanityCheck.AA"]) + float(tar["UserTrace.AA"])
        if abs(kgc_split - tar_kgc) > SPLIT_SUM_TOL_MS:
            issues.append("TAR_PCH KGC total does not match KeySanityCheck+UserTrace")
    if all(field in tar for field in ("KEKUpdate.CSP", "CTUpdate.CSP", "ReHash.CSP")):
        csp_split = float(tar["KEKUpdate.CSP"]) + float(tar["CTUpdate.CSP"]) + float(tar["ReHash.CSP"])
        if abs(csp_split - float(tar.get("Revocation.CSP", 0.0))) > SPLIT_SUM_TOL_MS:
            issues.append("TAR_PCH CSP total does not match KEKUpdate+CTUpdate+ReHash")

    if issues:
        raise RuntimeError(
            f"{path} uses simplified revocation baselines and cannot be used for Table 4: "
            + "; ".join(issues)
        )


def run_measurements(force: bool, max_mem_pct: float, poll_secs: float) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    for curve in CURVES:
        curve_dir = RAW / curve
        curve_dir.mkdir(parents=True, exist_ok=True)

        for policy in POLICIES:
            out = curve_dir / f"hrpch_u1024_a60_p{policy}.json"
            if force or not out.exists():
                run_cmd(
                    [
                        str(APP),
                        "--curve",
                        curve,
                        "--rsa-bits",
                        "3072",
                        "--attrs",
                        "60",
                        "--policy-attrs",
                        str(policy),
                        "--user-count",
                        "1024",
                        "--do-id",
                        "do1",
                        "--out",
                        str(out),
                    ],
                    HRPCH,
                    max_mem_pct,
                    poll_secs,
                )
            require_hrpch(out, curve)

        for exp in REV_USERS_EXP:
            users = 2**exp
            state_out = curve_dir / f"hrpch_state_{users}.json"
            rpch_out = curve_dir / f"rpch_rev_{users}.json"
            if force or not state_out.exists():
                run_cmd(
                    [
                        str(APP),
                        "--curve",
                        curve,
                        "--bench",
                        "state",
                        "--user-count",
                        str(users),
                        "--do-id",
                        "do1",
                        "--out",
                        str(state_out),
                    ],
                    HRPCH,
                    max_mem_pct,
                    poll_secs,
                )
            require_state(state_out, curve)

            if force or not rpch_out.exists():
                run_cmd(
                    [
                        str(RPCH_BENCH),
                        "--curve",
                        curve,
                        "--rsa-bits",
                        "3072",
                        "--users",
                        str(users),
                        "--attrs",
                        "60",
                        "--policy-attrs",
                        "20",
                        "--mode",
                        "revocation",
                        "--out",
                        str(rpch_out),
                    ],
                    RPCH_BENCH.parent,
                    max_mem_pct,
                    poll_secs,
                )
            require_rpch(rpch_out, curve)


def table3_adaptation() -> None:
    rows: list[list[str]] = []
    for p in POLICIES:
        m = read_json(RAW / "mnt224" / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        a = read_json(RAW / "a1" / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        rows.append(
            [
                str(p),
                fmt(m["ServerAdapt"]),
                fmt(a["ServerAdapt"]),
                fmt(m["InsiderAdapt(TEE)"]),
                fmt(a["InsiderAdapt(TEE)"]),
                fmt(m["UserAdapt"]),
                fmt(a["UserAdapt"]),
                fmt(m["Baseline.OwnerAdapt"]),
                fmt(a["Baseline.OwnerAdapt"]),
                fmt(m["Baseline.UserAdapt"]),
                fmt(a["Baseline.UserAdapt"]),
            ]
        )

    write_csv(
        TABLES / "table3_adaptation_latency.csv",
        [
            "policy",
            "2od_server_mnt_ms",
            "2od_server_a1_ms",
            "2od_tee_mnt_ms",
            "2od_tee_a1_ms",
            "2od_modifier_mnt_ms",
            "2od_modifier_a1_ms",
            "od_tee_mnt_ms",
            "od_tee_a1_ms",
            "od_modifier_mnt_ms",
            "od_modifier_a1_ms",
        ],
        rows,
    )

    tex = [
        r"\begin{tabular}{c rr rr rr rr rr}",
        r"\toprule",
        r"\multirow{3}{*}{$|policy|$} & \multicolumn{6}{c}{\textbf{CHET-2OA + ABE-2OD}} & \multicolumn{4}{c}{\textbf{CHET-OA + ABE-OD}} \\",
        r"\cmidrule(lr){2-7}\cmidrule(lr){8-11}",
        r" & \multicolumn{2}{c}{\textbf{Server}} & \multicolumn{2}{c}{\textbf{TEE}} & \multicolumn{2}{c}{\textbf{Modifier}} & \multicolumn{2}{c}{\textbf{TEE}} & \multicolumn{2}{c}{\textbf{Modifier}} \\",
        r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(lr){8-9}\cmidrule(lr){10-11}",
        r" & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} \\",
        r"\midrule",
    ]
    for row in rows:
        tex.append(" & ".join(row) + r" \\")
    tex += [r"\bottomrule", r"\end{tabular}"]
    (TABLES / "table3_adaptation_latency.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def table_hashcheck() -> None:
    rows: list[list[str]] = []
    for p in POLICIES:
        m = read_json(RAW / "mnt224" / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        a = read_json(RAW / "a1" / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
        rows.append(
            [
                str(p),
                fmt(m["FullReEncUserAdapt"]),
                fmt(a["FullReEncUserAdapt"]),
                fmt(m["UserAdapt"]),
                fmt(a["UserAdapt"]),
            ]
        )

    write_csv(
        TABLES / "table_hashcheck.csv",
        [
            "policy",
            "full_reenc_user_mnt_ms",
            "full_reenc_user_a1_ms",
            "hashcheck_user_mnt_ms",
            "hashcheck_user_a1_ms",
        ],
        rows,
    )
    tex = [
        r"\begin{tabular}{c rr rr}",
        r"\toprule",
        r"\multirow{2}{*}{$|policy|$} & \multicolumn{2}{c}{\textbf{Full Re-encryption Adapt}} & \multicolumn{2}{c}{\textbf{Hash-check Adapt}} \\",
        r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}",
        r" & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} \\",
        r"\midrule",
    ]
    for row in rows:
        tex.append(" & ".join(row) + r" \\")
    tex += [r"\bottomrule", r"\end{tabular}"]
    (TABLES / "table_hashcheck.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def table4_revocation() -> None:
    rows: list[list[str]] = []
    for exp in REV_USERS_EXP:
        users = 2**exp
        ms = read_json(RAW / "mnt224" / f"hrpch_state_{users}.json")["times_ms"]
        as_ = read_json(RAW / "a1" / f"hrpch_state_{users}.json")["times_ms"]
        require_strict_revocation_baselines(RAW / "mnt224" / f"rpch_rev_{users}.json")
        require_strict_revocation_baselines(RAW / "a1" / f"rpch_rev_{users}.json")
        mr = read_json(RAW / "mnt224" / f"rpch_rev_{users}.json")["schemes"]
        ar = read_json(RAW / "a1" / f"rpch_rev_{users}.json")["schemes"]
        m_tee_total = float(ms["State.Sign(KGC,revoked)"]) + float(ms["State.Check(TEE,revoked)"])
        a_tee_total = float(as_["State.Sign(KGC,revoked)"]) + float(as_["State.Check(TEE,revoked)"])
        rows.append(
            [
                rf"$2^{{{exp}}}$",
                fmt3(mr["EHR_RPCH"]["times_ms"]["EtdRevoke.KGC"]),
                fmt3(ar["EHR_RPCH"]["times_ms"]["EtdRevoke.KGC"]),
                fmt3(mr["EHR_RPCH"]["times_ms"]["EtdRevoke.CSP"]),
                fmt3(ar["EHR_RPCH"]["times_ms"]["EtdRevoke.CSP"]),
                fmt3(mr["EHR_RPCH"]["times_ms"]["EtdRevoke"]),
                fmt3(ar["EHR_RPCH"]["times_ms"]["EtdRevoke"]),
                fmt3(mr["TAR_PCH"]["times_ms"]["Revocation.KGC"]),
                fmt3(ar["TAR_PCH"]["times_ms"]["Revocation.KGC"]),
                fmt3(mr["TAR_PCH"]["times_ms"]["Revocation.CSP"]),
                fmt3(ar["TAR_PCH"]["times_ms"]["Revocation.CSP"]),
                fmt3(mr["TAR_PCH"]["times_ms"]["Revocation"]),
                fmt3(ar["TAR_PCH"]["times_ms"]["Revocation"]),
                fmt3(ms["State.Sign(KGC,revoked)"]),
                fmt3(as_["State.Sign(KGC,revoked)"]),
                fmt3(ms["State.Check(TEE,revoked)"]),
                fmt3(as_["State.Check(TEE,revoked)"]),
                fmt3(m_tee_total),
                fmt3(a_tee_total),
            ]
        )

    write_csv(
        TABLES / "table4_revocation.csv",
        [
            "users",
            "ehr_kgc_mnt_ms",
            "ehr_kgc_a1_ms",
            "ehr_server_mnt_ms",
            "ehr_server_a1_ms",
            "ehr_total_mnt_ms",
            "ehr_total_a1_ms",
            "tar_kgc_mnt_ms",
            "tar_kgc_a1_ms",
            "tar_server_mnt_ms",
            "tar_server_a1_ms",
            "tar_total_mnt_ms",
            "tar_total_a1_ms",
            "tee_kgc_mnt_ms",
            "tee_kgc_a1_ms",
            "tee_check_mnt_ms",
            "tee_check_a1_ms",
            "tee_total_mnt_ms",
            "tee_total_a1_ms",
        ],
        rows,
    )
    tex = [
        r"\begin{tabular}{c rr rr rr rr rr rr rr rr rr}",
        r"\toprule",
        r"\multirow{3}{*}{\textbf{$N$}} & \multicolumn{6}{c}{\textbf{EHR-RPCH}} & \multicolumn{6}{c}{\textbf{TAR-PCH}} & \multicolumn{6}{c}{\textbf{TEE-RPCH}} \\",
        r"\cmidrule(lr){2-7}\cmidrule(lr){8-13}\cmidrule(lr){14-19}",
        r" & \multicolumn{2}{c}{\textbf{KGC}} & \multicolumn{2}{c}{\textbf{Server}} & \multicolumn{2}{c}{\textbf{Total}} & \multicolumn{2}{c}{\textbf{KGC}} & \multicolumn{2}{c}{\textbf{Server}} & \multicolumn{2}{c}{\textbf{Total}} & \multicolumn{2}{c}{\textbf{KGC}} & \multicolumn{2}{c}{\textbf{TEE Check}} & \multicolumn{2}{c}{\textbf{Total}} \\",
        r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(lr){8-9}\cmidrule(lr){10-11}\cmidrule(lr){12-13}\cmidrule(lr){14-15}\cmidrule(lr){16-17}\cmidrule(lr){18-19}",
        r" & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} & \textbf{MNT} & \textbf{A1} \\",
        r"\midrule",
    ]
    for row in rows:
        tex.append(" & ".join(row) + r" \\")
    tex += [r"\bottomrule", r"\end{tabular}"]
    (TABLES / "table4_revocation.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def theory_table() -> None:
    rows = [
        ["FB-PCH", r"$O(|S|)$", r"$O(|policy|)$", r"$O(|policy|)$"],
        ["EHR-RPCH", r"$O(|S|+\log N)$", r"$O(|policy|)$", r"KGC token + server ciphertext update"],
        ["PNITCH", r"$O(|S|)$", r"$O(|policy|)$", r"authorization token + adapt"],
        ["RPCH-XNM'21", r"$O(|S|+\log N)$", r"$O(|policy|)$", r"$O(|policy|+\log N)$"],
        ["TAR-PCH", r"$O(|S|+\log N)$", r"$O(|policy|)$", r"KGC trace + server update"],
        ["TPCH", r"$O(|S|+\log N)$", r"$O(|policy|)$", r"$O(|policy|+\log N)$"],
        ["TEE-RPCH", r"$O(|S|)$", r"$O(|policy|)$", r"server Transform1 + TEE Transform2/check + user hash-check"],
    ]
    tex = [r"\begin{tabular}{lccc}", r"\toprule", r"\textbf{Scheme} & \textbf{KeyGen} & \textbf{Hash} & \textbf{Adapt / Revocation Path} \\", r"\midrule"]
    for row in rows:
        tex.append(" & ".join(row) + r" \\")
    tex += [r"\bottomrule", r"\end{tabular}"]
    (TABLES / "table1_theory.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def build_tables() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    theory_table()
    table3_adaptation()
    table_hashcheck()
    table4_revocation()


def build_figures() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.family": _load_times_font(),
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "mathtext.fontset": "stix",
            "mathtext.rm": "Times New Roman",
            "mathtext.it": "Times New Roman:italic",
            "mathtext.bf": "Times New Roman:bold",
            "font.size": 13,
            "axes.labelsize": 13,
            "axes.titlesize": 13,
            "legend.fontsize": 12,
            "xtick.labelsize": 12,
            "ytick.labelsize": 12,
            "legend.handlelength": 2.0,
            "legend.handletextpad": 0.5,
            "legend.columnspacing": 0.9,
            "lines.markersize": 4.6,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )

    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.7), sharex=True)
    for ax, curve, title in zip(axes, CURVES, ["MNT224", "A1 (ss1024)"]):
        vals = {k: [] for k in ["ServerAdapt", "InsiderAdapt(TEE)", "UserAdapt", "Baseline.UserAdapt"]}
        for p in POLICIES:
            t = read_json(RAW / curve / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
            for k in vals:
                vals[k].append(float(t[k]))
        ax.plot(POLICIES, vals["ServerAdapt"], marker="o", label="2OD server")
        ax.plot(POLICIES, vals["InsiderAdapt(TEE)"], marker="s", label="2OD TEE")
        ax.plot(POLICIES, vals["UserAdapt"], marker="^", label="2OD modifier")
        ax.plot(POLICIES, vals["Baseline.UserAdapt"], marker="D", label="OD modifier")
        ax.set_title(title)
        ax.set_xlabel(r"$|policy|$")
        ax.set_yscale("log")
        ax.grid(True, alpha=0.25)
    axes[0].set_ylabel("Latency (ms, log scale)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.05), frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(FIGURES / "adaptation_latency.pdf", bbox_inches="tight")
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.7), sharex=True)
    for ax, curve, title in zip(axes, CURVES, ["MNT224", "A1 (ss1024)"]):
        full = []
        hashcheck = []
        for p in POLICIES:
            t = read_json(RAW / curve / f"hrpch_u1024_a60_p{p}.json")["times_ms"]
            full.append(float(t["FullReEncUserAdapt"]))
            hashcheck.append(float(t["UserAdapt"]))
        ax.plot(POLICIES, full, marker="o", color="#7f3c8d", label="Full re-encryption adapt")
        ax.plot(POLICIES, hashcheck, marker="^", color="#3969ac", label="Hash-check adapt")
        ax.set_title(title)
        ax.set_xlabel(r"$|policy|$")
        ax.grid(True, alpha=0.25)
    axes[0].set_ylabel("User-side cost (ms)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.05), frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.savefig(FIGURES / "hashcheck_vs_reenc.pdf", bbox_inches="tight")
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.7), sharex=True)
    for ax, curve, title in zip(axes, CURVES, ["MNT224", "A1 (ss1024)"]):
        xs = REV_USERS_EXP
        ehr = []
        tar = []
        tee = []
        for exp in xs:
            users = 2**exp
            state = read_json(RAW / curve / f"hrpch_state_{users}.json")["times_ms"]
            rp = read_json(RAW / curve / f"rpch_rev_{users}.json")["schemes"]
            ehr.append(float(rp["EHR_RPCH"]["times_ms"]["EtdRevoke"]))
            tar.append(float(rp["TAR_PCH"]["times_ms"]["Revocation"]))
            tee.append(float(state["State.Sign(KGC,revoked)"]) + float(state["State.Check(TEE,revoked)"]))
        ax.plot(xs, ehr, marker="o", label="EHR-RPCH")
        ax.plot(xs, tar, marker="s", label="TAR-PCH")
        ax.plot(xs, tee, marker="^", label="TEE-RPCH")
        ax.set_title(title)
        ax.set_xlabel(r"$\log_2 N$")
        ax.set_yscale("log")
        ax.grid(True, alpha=0.25)
    axes[0].set_ylabel("Revocation cost (ms, log scale)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.05), frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.savefig(FIGURES / "revocation_comparison.pdf", bbox_inches="tight")
    plt.close(fig)


def build_audit() -> None:
    lines = [
        "# Targeted Table Field Mapping Audit",
        "",
        "All HR-PCH values in this folder were regenerated from `hr_pch_sgx/app` in SGX hardware mode.",
        "",
        "## Required implementation checks",
        "",
        f"- Expected HR-PCH version: `{EXPECTED_HRPCH_VERSION}`.",
        "- Required JSON flags: `sgx_mode=HW`, `tee_hk_decrypt=true`, `tee_transform2=true`, `tee_etd2_check=true`, `user_final_hash_check=true`.",
        "- Server column for `CHET-2OA + ABE-2OD`: `times_ms.ServerAdapt`, whose code scope is `CHET-mu-plus-FAME-2OD-Transform1-only`.",
        "- TEE column for `CHET-2OA + ABE-2OD`: `times_ms.InsiderAdapt(TEE)`, whose code scope is state verification, HK decryption, FAME-2OD Transform2, IBE share decryption, and ETD2 consistency checking.",
        "- Modifier column for `CHET-2OA + ABE-2OD`: `times_ms.UserAdapt`, whose code scope is FAME-2OD final decryption, symmetric decryption of the user trapdoor share, RSA exponentiation, and final hash-check verification.",
        "- TEE column for `CHET-OA + ABE-OD`: `times_ms.Baseline.OwnerAdapt` from the no-cloud baseline path.",
        "- Modifier column for `CHET-OA + ABE-OD`: `times_ms.Baseline.UserAdapt` from the no-cloud baseline path.",
        "- Hash-check comparison uses the newly measured `FullReEncUserAdapt` and `FullReEncUserAdapt.ReEncryptCheck` fields, not the older AES-only `LegacyUserAdapt` field.",
        "- EHR-RPCH/TAR-PCH revocation values come from `rpch_bench` with `--mode revocation`; only these two server-assisted revocation schemes are included in Table 4.",
        "",
        "## Important caveat",
        "",
        "The strict full re-encryption comparison re-runs randomized FAME-2OD encryption and records its real cost. Exact ciphertext equality is not expected without storing or replaying encryption randomness, so the table uses timing values rather than a successful equality predicate.",
        "",
    ]
    (OUT / "field_mapping_audit.md").write_text("\n".join(lines), encoding="utf-8")


def build_report() -> Path:
    REPORT.mkdir(parents=True, exist_ok=True)
    tex = r"""
\PassOptionsToPackage{table}{xcolor}
\documentclass[sigconf]{acmart}
\setcopyright{none}
\settopmatter{printacmref=false}
\renewcommand\footnotetextcopyrightpermission[1]{}
\usepackage{booktabs}
\usepackage{multirow}
\usepackage{graphicx}
\usepackage{amsmath}
\usepackage{placeins}
\newcommand{\TableStyle}{\setlength{\tabcolsep}{3pt}\renewcommand{\arraystretch}{1.06}}
\newcommand{\TableStyleTight}{\setlength{\tabcolsep}{2.2pt}\renewcommand{\arraystretch}{1.03}}

\title{TEE-RPCH Targeted Experimental Report}
\author{Anonymous}
\affiliation{\institution{Anonymous Institution}}

\begin{document}
\maketitle

\section{Experimental Scope}
This report regenerates the table-oriented experiments using the corrected TEE-RPCH implementation. The implementation tag is \texttt{tee-rpch-v10-sgx-2od-split-full-reenc}; every TEE-RPCH data point is validated to use SGX hardware mode. The measured split is: the server performs CHET intermediate computation and FAME-2OD Transform1, the enclave performs state verification, HK decryption, FAME-2OD Transform2, IBE-protected share recovery, and ETD2 consistency checking, and the modifier performs final decryption plus hash-check finalization.

\begin{table*}[t]
\centering
\caption{Theory-level comparison of representative revocable PCH/RPCH schemes.}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{../tables/table1_theory.tex}}
\end{table*}

\section{Outsourcing Baseline}
Table~\ref{tab:adapt-targeted} follows the paper table style and separates the server, TEE, and modifier costs instead of folding TEE work into the server column. Fig.~\ref{fig:adapt-targeted} plots the same latency split on both curves.

\begin{table*}[t]
\centering
\caption{Adaptation latency across policy sizes (ms), $|\mathbb{S}|=60$.}
\label{tab:adapt-targeted}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{../tables/table3_adaptation_latency.tex}}
\end{table*}

\begin{figure*}[t]
\centering
\includegraphics[width=0.86\textwidth]{../figures/adaptation_latency.pdf}
\caption{Adaptation latency split for the outsourced and no-cloud baselines.}
\label{fig:adapt-targeted}
\end{figure*}

\section{Hash-check Trick}
Table~\ref{tab:hashcheck-targeted} isolates the user-side trick. Both columns measure only the modifier-side Adapt finalization. The original fallback performs a full FAME-2OD re-encryption-based consistency check after recovering the plaintext/key, whereas our construction replaces that final re-encryption with a hash-check verification. The strict re-encryption path is randomized, so the equality predicate is not used as a correctness claim; the table reports the real user-side cost of that path.

\begin{table*}[t]
\centering
\caption{Modifier-side Adapt cost with full re-encryption checking versus hash-checking (ms).}
\label{tab:hashcheck-targeted}
\scriptsize
\TableStyle
\resizebox{\textwidth}{!}{\input{../tables/table_hashcheck.tex}}
\end{table*}

\begin{figure*}[t]
\centering
\includegraphics[width=0.86\textwidth]{../figures/hashcheck_vs_reenc.pdf}
\caption{Modifier-side Adapt cost of full re-encryption checking and hash-checking.}
\label{fig:hashcheck-targeted}
\end{figure*}

\section{Revocation}
Table~\ref{tab:revocation-targeted} compares TEE-RPCH only with server-assisted revocation designs, EHR-RPCH and TAR-PCH. Pure cryptographic non-outsourced schemes are intentionally excluded from this revocation table.

\begin{table*}[t]
\centering
\caption{Revocation cost for one revoked modifier (ms).}
\label{tab:revocation-targeted}
\scriptsize
\TableStyleTight
\resizebox{\textwidth}{!}{\input{../tables/table4_revocation.tex}}
\end{table*}

\begin{figure*}[t]
\centering
\includegraphics[width=0.86\textwidth]{../figures/revocation_comparison.pdf}
\caption{Revocation cost for EHR-RPCH, TAR-PCH, and TEE-RPCH.}
\label{fig:revocation-targeted}
\end{figure*}

\FloatBarrier
\end{document}
"""
    tex_path = REPORT / "targeted_experiment_report.tex"
    tex_path.write_text(tex.strip() + "\n", encoding="utf-8")
    for _ in range(2):
        subprocess.run(
            ["xelatex", "-interaction=nonstopmode", "-halt-on-error", tex_path.name],
            cwd=str(REPORT),
            check=True,
        )
    return REPORT / "targeted_experiment_report.pdf"


def main() -> int:
    ap = argparse.ArgumentParser(description="Run corrected targeted measurements and build the table-style PDF report.")
    ap.add_argument("--force", action="store_true", help="Rerun all raw measurements.")
    ap.add_argument("--skip-run", action="store_true", help="Only rebuild tables/figures/report from existing raw JSON.")
    ap.add_argument("--max-mem-pct", type=float, default=95.0)
    ap.add_argument("--mem-poll-secs", type=float, default=2.0)
    args = ap.parse_args()

    if not APP.exists():
        raise RuntimeError(f"Missing SGX app: {APP}")
    if not RPCH_BENCH.exists():
        raise RuntimeError(f"Missing rpch_bench: {RPCH_BENCH}")

    OUT.mkdir(parents=True, exist_ok=True)
    if not args.skip_run:
        run_measurements(args.force, args.max_mem_pct, max(0.2, args.mem_poll_secs))
    build_tables()
    build_figures()
    build_audit()
    pdf = build_report()
    print(f"Wrote PDF: {pdf}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
