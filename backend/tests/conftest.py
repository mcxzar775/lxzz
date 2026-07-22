from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import secrets

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.security import hash_password
from app.db.base import Base
from app.main import create_app
from app.models.auth import User
from app.models.enums import UserRole


@dataclass(frozen=True)
class UserCredentials:
    super_username: str
    super_password: str
    admin_username: str
    admin_password: str
    viewer_username: str
    viewer_password: str


@pytest.fixture
def test_users() -> UserCredentials:
    return UserCredentials(
        super_username="superadmin",
        super_password=secrets.token_urlsafe(24),
        admin_username="operator",
        admin_password=secrets.token_urlsafe(24),
        viewer_username="observer",
        viewer_password=secrets.token_urlsafe(24),
    )


@pytest.fixture
def app(tmp_path: Path, test_users: UserCredentials) -> Iterator[FastAPI]:
    database_path = tmp_path / "test.db"
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{database_path}",
        cookie_secure=False,
        login_max_attempts=5,
        login_lock_minutes=15,
        openvpn_config_directory=str(tmp_path / "openvpn-configs"),
        socks_config_directory=str(tmp_path / "socks-configs"),
        credential_encryption_key_file=str(tmp_path / "credential.key"),
        enable_real_network=False,
    )
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    factory: sessionmaker[Session] = application.state.session_factory
    with factory() as db:
        db.add_all(
            [
                User(
                    username=test_users.super_username,
                    password_hash=hash_password(test_users.super_password),
                    role=UserRole.SUPER_ADMIN,
                ),
                User(
                    username=test_users.admin_username,
                    password_hash=hash_password(test_users.admin_password),
                    role=UserRole.ADMIN,
                ),
                User(
                    username=test_users.viewer_username,
                    password_hash=hash_password(test_users.viewer_password),
                    role=UserRole.VIEWER,
                ),
            ]
        )
        db.commit()
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, "remember_me": False},
    )
    assert response.status_code == 200, response.text
    csrf_token = client.cookies.get("vpngate_csrf")
    assert isinstance(csrf_token, str) and csrf_token
    return csrf_token
