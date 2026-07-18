import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

project_root_string = str(PROJECT_ROOT)

if project_root_string not in sys.path:
    sys.path.insert(
        0,
        project_root_string,
    )