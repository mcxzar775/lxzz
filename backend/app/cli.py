import argparse
import getpass
import os
from pathlib import Path
import stat

from alembic import command
from alembic.config import Config
from sqlalchemy import select, update
from sqlalchemy.engine import make_url

from app.core.config import Settings, get_settings
from app.core.security import hash_password, normalize_username
from app.db.base import utcnow
from app.db.session import create_database_engine, create_session_factory
from app.models.auth import User, UserSession
from app.models.enums import UserRole
from app.services.network.socks5 import CredentialCipher
from app.services.audit import record_audit


BACKEND_DIR = Path(__file__).resolve().parents[1]


def _password_from_file(path_value: str) -> str:
    path = Path(path_value)
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size < 12
            or metadata.st_size > 1024
        ):
            raise SystemExit("password input file is unsafe")
        raw_password = os.read(descriptor, 1025)
        password = raw_password.decode("utf-8")
        if "\x00" in password or "\n" in password or "\r" in password:
            raise SystemExit("password input file is unsafe")
        return password
    except (OSError, UnicodeError) as exc:
        raise SystemExit("password input file is unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _read_new_password(*, password_file: str | None, environment_key: str) -> str:
    if password_file is not None:
        return _password_from_file(password_file)
    environment_password = os.getenv(environment_key)
    if environment_password:
        return environment_password
    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm new password: ")
    if password != confirmation:
        raise SystemExit("passwords do not match")
    return password


def _ensure_sqlite_parent(database_url: str) -> None:
    if not database_url.startswith("sqlite") or ":memory:" in database_url:
        return
    database_name = make_url(database_url).database
    if not database_name:
        return
    database_path = Path(database_name)
    if not database_path.is_absolute():
        database_path = Path.cwd() / database_path
    database_path.parent.mkdir(parents=True, exist_ok=True)


def init_db(settings: Settings) -> None:
    _ensure_sqlite_parent(settings.database_url)
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["database_url"] = settings.database_url
    command.upgrade(config, "head")


def init_secrets(settings: Settings) -> None:
    CredentialCipher.load_or_create(settings.credential_encryption_key_file)
    print("credential encryption key is ready")


def create_admin(
    settings: Settings,
    username_value: str | None,
    password_file: str | None = None,
) -> None:
    username_input = username_value or os.getenv("VPNGATE_ADMIN_USERNAME") or input(
        "Administrator username: "
    )
    username = normalize_username(username_input)
    password = _read_new_password(
        password_file=password_file,
        environment_key="VPNGATE_ADMIN_PASSWORD",
    )
    password_hash = hash_password(password)
    engine = create_database_engine(settings.database_url)
    factory = create_session_factory(engine)
    with factory() as db:
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            raise SystemExit("administrator username already exists")
        db.add(
            User(
                username=username,
                password_hash=password_hash,
                role=UserRole.SUPER_ADMIN,
                is_active=True,
            )
        )
        db.commit()
    engine.dispose()
    print(f"administrator '{username}' created")


def reset_password(
    settings: Settings,
    username_value: str | None,
    password_file: str | None = None,
) -> None:
    username_input = (
        username_value
        or os.getenv("VPNGATE_RESET_USERNAME")
        or input("Username to reset: ")
    )
    username = normalize_username(username_input)
    password = _read_new_password(
        password_file=password_file,
        environment_key="VPNGATE_RESET_PASSWORD",
    )
    password_hash = hash_password(password)
    engine = create_database_engine(settings.database_url)
    factory = create_session_factory(engine)
    with factory() as db:
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            raise SystemExit("user not found")
        user.password_hash = password_hash
        user.password_changed_at = utcnow()
        db.execute(
            update(UserSession)
            .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        record_audit(
            db,
            action="user.password_reset_cli",
            status="success",
            target_type="user",
            target_id=str(user.id),
            details={"sessions_revoked": True},
        )
        db.commit()
    engine.dispose()
    print(f"password reset for '{username}'; active sessions revoked")


def list_connection_ids(settings: Settings) -> None:
    from app.models.network import VPNConnection

    engine = create_database_engine(settings.database_url)
    factory = create_session_factory(engine)
    with factory() as db:
        identifiers = db.scalars(select(VPNConnection.id).order_by(VPNConnection.id)).all()
    engine.dispose()
    for identifier in identifiers:
        print(identifier)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="apply Alembic migrations")
    subparsers.add_parser("init-secrets", help="create required application keys")
    subparsers.add_parser("has-users", help=argparse.SUPPRESS)
    create = subparsers.add_parser("create-admin", help="create the first super administrator")
    create.add_argument("--username")
    create.add_argument("--password-file", help=argparse.SUPPRESS)
    reset = subparsers.add_parser("reset-password", help="reset a user password")
    reset.add_argument("--username")
    reset.add_argument("--password-file", help=argparse.SUPPRESS)
    subparsers.add_parser("list-connection-ids", help=argparse.SUPPRESS)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = get_settings()
    if args.command == "init-db":
        init_db(settings)
    elif args.command == "init-secrets":
        init_secrets(settings)
    elif args.command == "has-users":
        engine = create_database_engine(settings.database_url)
        factory = create_session_factory(engine)
        with factory() as db:
            has_users = db.scalar(select(User.id).limit(1)) is not None
        engine.dispose()
        raise SystemExit(0 if has_users else 1)
    elif args.command == "create-admin":
        create_admin(settings, args.username, args.password_file)
    elif args.command == "reset-password":
        reset_password(settings, args.username, args.password_file)
    elif args.command == "list-connection-ids":
        list_connection_ids(settings)


if __name__ == "__main__":
    main()
