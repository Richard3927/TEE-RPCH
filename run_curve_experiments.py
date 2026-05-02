#!/usr/bin/env python3
"""Compatibility wrapper for the organized experiment suite.

Use `experiments/run_all.py` for new runs. This file is kept so older
commands in notes and scripts continue to work.
"""

from pathlib import Path
import runpy


target = Path(__file__).resolve().parent / "experiments" / "run_all.py"
runpy.run_path(str(target), run_name="__main__")
