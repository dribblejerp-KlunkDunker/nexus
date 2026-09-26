"""Pytest bootstrap: put scripts/ on sys.path so the modules import cleanly.

The NEXUS runtime adds scripts/ to sys.path at startup; tests replicate that
instead of installing anything. Also pins a clean environment for policy.py.
"""

import os
import sys

SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

# policy.py reads NEXUS_THRESHOLD at import time; tests need the default.
os.environ.pop("NEXUS_THRESHOLD", None)
