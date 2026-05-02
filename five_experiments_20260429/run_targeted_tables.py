#!/usr/bin/env python3
from pathlib import Path
import runpy


target = Path(__file__).resolve().parents[1] / "experiments" / "exp3_hashcheck_efficiency.py"
runpy.run_path(str(target), run_name="__main__")
