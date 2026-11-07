"""Create persistent accounts for the manual LAN demo."""

import argparse
import json
import secrets
from dataclasses import asdict
from getpass import getpass
from pathlib import Path

from config import PROJECT_ROOT
from security import generate_key, hash_password
from server import UserRecord


def create_demo_credentials(count: int, password: str) -> tuple[list[UserRecord], dict[int, bytes]]:
    """Generate a separate salt and encryption key for each demo account."""
    if type(count) is not int or not 1 <= count <= 65535:
        raise ValueError("count must be between 1 and 65535")
    users, keys = [], {}
    for number in range(1, count + 1):
        salt = secrets.token_bytes(16)
        users.append(
            UserRecord(f"client{number:02}", number, salt.hex(), hash_password(password, salt))
        )
        keys[number] = generate_key()
    return users, keys


def write_credentials(users: list[UserRecord], keys: dict[int, bytes], output: Path) -> None:
    """Write credentials exclusively and roll back partial writes."""
    if not users or {user.key_id for user in users} != set(keys):
        raise ValueError("Users and keys must match")
    names = [user.username for user in users]
    if len(set(names)) != len(names) or len(keys) != len(users):
        raise ValueError("Duplicate account or key ID")
    if any(name != f"client{user.key_id:02}" for name, user in zip(names, users, strict=True)):
        raise ValueError("Provision accepts generated clientNN accounts only")
    encoded = {str(key): value.decode("ascii") for key, value in keys.items()}
    documents = {"users.json": [asdict(user) for user in users], "server.keys.json": encoded}
    documents.update(
        {
            f"{user.username}.keys.json": {str(user.key_id): encoded[str(user.key_id)]}
            for user in users
        }
    )
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() or (output / name).is_symlink() for name in documents):
        raise FileExistsError("Credentials already exist; choose an empty output directory")
    created = []
    try:
        for name, content in documents.items():
            path = output / name
            with path.open("x", encoding="utf-8") as destination:
                created.append(path)
                path.chmod(0o600)
                json.dump(content, destination, indent=2)
                destination.write("\n")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["provision"])
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "config/secrets")
    args = parser.parse_args()
    try:
        users, keys = create_demo_credentials(args.count, getpass("Demo password: "))
        write_credentials(users, keys, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Created {len(users)} accounts in {args.output}")


if __name__ == "__main__":
    main()
