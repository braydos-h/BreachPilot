"""Entry point for the TUI. Run with: python -m tui"""

import sys
from pathlib import Path

from tui.app import run


if __name__ == "__main__":
    workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    run(workspace)
