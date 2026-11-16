"""Entry point: ``python -m sso_local <command>``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
