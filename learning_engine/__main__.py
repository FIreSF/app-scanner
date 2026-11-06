"""Allow `python -m learning_engine ...`."""

import sys

from learning_engine.cli import main

if __name__ == "__main__":
    sys.exit(main())
