import argparse
import getpass
import sys

from sqlalchemy.orm import Session

from sentinel.accounts import create_user
from sentinel.config import Settings
from sentinel.db import make_engine, require_schema


def main() -> int:
    parser = argparse.ArgumentParser(description="Project Sentinel local administration")
    subcommands = parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create-user", help="Create a local administrator")
    create.add_argument("username")
    args = parser.parse_args()
    engine = make_engine(Settings().database_path)
    try:
        require_schema(engine)
        password = getpass.getpass("Password (12-128 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match.")
        with Session(engine) as db:
            user = create_user(db, args.username, password)
            print(f"Created administrator '{user.username}'.")
        return 0
    except (RuntimeError, ValueError, EOFError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
