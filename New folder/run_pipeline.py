"""Simple runner for PipelineController.

Usage:
    python run_pipeline.py <directory1> [<directory2> ...]

This will start the pipeline with default settings and print progress to stdout.
"""
import sys
import time
from pathlib import Path

# Ensure `app/` is importable as a top-level package so modules that use
# non-relative imports like `from security_io import ...` still work when
# running this script from `New folder/`.
sys.path.insert(0, str(Path(__file__).parent / 'app'))
sys.path.insert(0, str(Path(__file__).parent))

from app.pipeline_controller import PipelineController


def main(argv):
    if len(argv) < 2:
        print("Usage: python run_pipeline.py <dir1> [<dir2> ...]")
        return 1

    dirs = argv[1:]
    # Resolve directories
    dirs = [str(Path(d).resolve()) for d in dirs]

    pc = PipelineController()
    pc.start_scan(dirs)

    try:
        # Wait until producer finishes and workers complete.
        while True:
            time.sleep(2)

            # Simple interactive stop: Ctrl-C
    except KeyboardInterrupt:
        print("Stopping scan...")
        pc.stop_scan()

    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
