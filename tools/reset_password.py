"""Reset passwords for selected local demo accounts."""

import argparse
import json
import secrets
from getpass import getpass
from pathlib import Path
from tempfile import NamedTemporaryFile

from config import PROJECT_ROOT
from security import hash_password


def reset_password(path, names, password):
    users = json.loads(path.read_text(encoding="utf-8"))
    missing = set(names).difference(user["username"] for user in users)
    if missing:
        raise ValueError(f"Unknown accounts: {', '.join(sorted(missing))}")
    for user in users:
        if user["username"] in names:
            salt = secrets.token_bytes(16)
            user.update(password_salt=salt.hex(), password_hash=hash_password(password, salt))
    with NamedTemporaryFile(dir=path.parent, delete=False) as temp:
        temp_path = Path(temp.name)
    try:
        temp_path.write_text(json.dumps(users, indent=2) + "\n", encoding="utf-8")
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("accounts", nargs="+")
    args = parser.parse_args()
    password = getpass("New password: ")
    if password != getpass("Confirm password: "):
        parser.exit(1, "Passwords do not match.\n")
    try:
        reset_password(PROJECT_ROOT / "config/secrets/users.json", args.accounts, password)
    except (ValueError, OSError) as error:
        parser.exit(1, f"{error}\n")
    print("Password updated for", ", ".join(args.accounts))
