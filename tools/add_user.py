"""Add one account to an existing demo server while it is stopped."""

import argparse
import json
import secrets
from dataclasses import asdict
from getpass import getpass
from pathlib import Path
from tempfile import TemporaryDirectory

from config import PROJECT_ROOT
from protocol import validate_username
from security import generate_key, hash_password, load_keyring
from server import UserRecord


def add_user(folder: Path, username: str, password: str) -> tuple[int, Path]:
    validate_username(username)
    users_path = folder / "users.json"
    keys_path = folder / "server.keys.json"
    lock = folder / ".add-user.lock"
    lock.mkdir()
    try:
        users = json.loads(users_path.read_text(encoding="utf-8"))
        keys = load_keyring(keys_path)
        if any(user["username"] == username for user in users):
            raise ValueError("Username already exists")
        used = set(keys) | {user["key_id"] for user in users}
        key_id = next((i for i in range(1, 65536) if i not in used), None)
        if key_id is None:
            raise ValueError("No free key ID")
        client_path = folder / f"client{key_id:02}.keys.json"
        salt = secrets.token_bytes(16)
        users.append(
            asdict(UserRecord(username, key_id, salt.hex(), hash_password(password, salt)))
        )
        keys[key_id] = generate_key()
        encoded = {str(i): k.decode("ascii") for i, k in keys.items()}
        with TemporaryDirectory(dir=folder) as scratch:
            stage = Path(scratch)
            backup = stage / "original.keys.json"
            backup.write_bytes(keys_path.read_bytes())
            new_keys, new_users = stage / "keys.json", stage / "users.json"
            new_keys.write_text(json.dumps(encoded, indent=2), encoding="utf-8")
            new_users.write_text(json.dumps(users, indent=2), encoding="utf-8")
            dest = client_path.open("x", encoding="utf-8")
            try:
                with dest:
                    json.dump({str(key_id): encoded[str(key_id)]}, dest)
                new_keys.replace(keys_path)
                try:
                    new_users.replace(users_path)
                except BaseException:
                    backup.replace(keys_path)
                    raise
            except BaseException:
                client_path.unlink()
                raise
        return key_id, client_path
    finally:
        lock.rmdir()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    args = parser.parse_args()
    password = getpass("New password: ")
    if password != getpass("Confirm password: "):
        parser.exit(1, "Passwords do not match.\n")
    try:
        key_id, path = add_user(PROJECT_ROOT / "config/secrets", args.username, password)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Created {args.username}: key_id={key_id}, keyring={path}")
