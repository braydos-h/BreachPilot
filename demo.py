import subprocess
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).parent / "demo"
URL = "http://localhost:5173"


def main() -> int:
    if not (DEMO_DIR / "node_modules").is_dir():
        print("Installing demo dependencies...")
        subprocess.check_call("npm install", shell=True, cwd=DEMO_DIR)
    print(f"Starting demo website at {URL} (Ctrl+C to stop)")
    try:
        return subprocess.call("npm run dev", shell=True, cwd=DEMO_DIR)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
