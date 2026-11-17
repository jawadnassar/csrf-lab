"""Entry point: python3 -m csrf_lab"""

from __future__ import annotations

from .config import parse_args
from .server import serve


def main() -> None:
    config = parse_args()
    serve(config)


if __name__ == "__main__":
    main()
