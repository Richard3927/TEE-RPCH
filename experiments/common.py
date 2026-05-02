from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
HRPCH_DIR = PROJECT_ROOT / "hr_pch_sgx"
RPCH_BENCH_DIR = PROJECT_ROOT / "rpch_bench"


def run(cmd: list[str], *, cwd: Path) -> None:
    print("+", " ".join(str(x) for x in cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True, stdout=sys.stdout, stderr=sys.stderr)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def needs_curve(path: Path, curve: str) -> bool:
    if not path.exists():
        return True
    try:
        data = read_json(path)
    except Exception:
        return True
    return data.get("params", {}).get("curve") != curve


def build_all() -> None:
    run(["make", "SGX_MODE=HW", "SGX_DEBUG=0", f"-j{os.cpu_count() or 4}"], cwd=HRPCH_DIR)
    run(["make", "DEBUG=0", f"-j{os.cpu_count() or 4}"], cwd=RPCH_BENCH_DIR)


def app_path() -> str:
    return str((HRPCH_DIR / "app").resolve())


def rpch_bench_path() -> str:
    return str((RPCH_BENCH_DIR / "rpch_bench").resolve())
