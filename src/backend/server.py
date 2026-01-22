from __future__ import annotations

import os

from dotenv import load_dotenv

from app import create_app


def main() -> None:
    load_dotenv()
    app = create_app()
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug)


if __name__ == "__main__":
    main()
