#!/usr/bin/env python3
"""Backward-compatible entry point of the LEGACY casasmooth webhook harness.

``python3 grd_simulator.py --target ... --token ...`` keeps working without
installing anything (standard library only). It is NOT a SmartGridready test:
for that, install the package and use ``grd-sgr run`` (see README.md).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from grd_sgr.legacy_simulator import main  # noqa: E402

if __name__ == "__main__":
    main()
