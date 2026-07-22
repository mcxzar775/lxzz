import secrets
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.cli import _password_from_file, reset_password
from app.core.security import verify_password
from app.models.auth import AuditLog, User, UserSession

from conftest import UserCredentials, login


def test_login_sets_secure_session_shape_and_returns_me(
    client: TestClient, test_users: UserCredentials
) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": test_users.super_username,
            "password": test_users.super_password,
            "remember_me": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "SUPER_ADMIN"
    assert "users:manage" in response.json()["permissions"]
    cookie_headers = response.headers.get_list("set-cookie")
    session_cookie = next(item for item in cookie_headers if item.startswith("vpngate_session="))
    csrf_cookie = next(item for item in cookie_headers if item.startswith("vpngate_csrf="))
    assert "HttpOnly" in session_cookie
    assert "SameSite=lax" in session_cookie
    assert "Max-Age=" in session_cookie
    assert "HttpOnly" not in csrf_cookie

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == test_users.super_username


def test_invalid_login_is_generic_and_rate_limited(
    client: TestClient, test_users: UserCredentials
) -> None:
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": test_users.viewer_username, "password": "wrong"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
    locked = client.post(
        "/api/v1/auth/login",
        json={
            "username": test_users.viewer_username,
            "password": test_users.viewer_password,
        },
    )
    assert locked.status_code == 429
    assert "password" not in locked.text.lower()


def test_logout_requires_csrf_and_revokes_session(
    client: TestClient, test_users: UserCredentials
) -> None:
    csrf = login(client, test_users.viewer_username, test_users.viewer_password)
    rejected = client.post("/api/v1/auth/logout")
    assert rejected.status_code == 403
    response = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401


def test_password_change_revokes_other_sessions(
    app: FastAPI, test_users: UserCredentials
) -> None:
    with TestClient(app) as first, TestClient(app) as second:
        first_csrf = login(first, test_users.admin_username, test_users.admin_password)
        login(second, test_users.admin_username, test_users.admin_password)

        replacement_password = secrets.token_urlsafe(24)
        changed = first.post(
            "/api/v1/auth/password",
            headers={"X-CSRF-Token": first_csrf},
            json={
                "current_password": test_users.admin_password,
                "new_password": replacement_password,
            },
        )
        assert changed.status_code == 204
        assert first.get("/api/v1/auth/me").status_code == 200
        assert second.get("/api/v1/auth/me").status_code == 401


def test_offline_password_reset_revokes_sessions_and_redacts_password(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    login(client, test_users.viewer_username, test_users.viewer_password)
    replacement = secrets.token_urlsafe(24)
    password_file = tmp_path / "password-input"
    password_file.write_text(replacement, encoding="utf-8")
    password_file.chmod(0o600)

    reset_password(
        app.state.settings,
        test_users.viewer_username,
        str(password_file),
    )

    assert replacement not in capsys.readouterr().out
    assert not password_file.exists()
    assert client.get("/api/v1/auth/me").status_code == 401
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        user = db.scalar(select(User).where(User.username == test_users.viewer_username))
        assert user is not None
        assert verify_password(replacement, user.password_hash)
        audit = db.scalar(
            select(AuditLog).where(AuditLog.action == "user.password_reset_cli")
        )
        assert audit is not None
        assert replacement not in str(audit.details)


def test_password_input_file_rejects_permissive_mode_and_symlink(tmp_path: Path) -> None:
    permissive = tmp_path / "permissive-password"
    permissive.write_text(secrets.token_urlsafe(24), encoding="utf-8")
    permissive.chmod(0o644)
    with pytest.raises(SystemExit, match="unsafe"):
        _password_from_file(str(permissive))
    assert not permissive.exists()

    target = tmp_path / "target-password"
    target.write_text(secrets.token_urlsafe(24), encoding="utf-8")
    target.chmod(0o600)
    linked = tmp_path / "linked-password"
    linked.symlink_to(target)
    with pytest.raises(SystemExit, match="unsafe"):
        _password_from_file(str(linked))
    assert target.exists()
    assert not linked.exists()


def test_auth_events_are_audited(
    app: FastAPI, client: TestClient, test_users: UserCredentials
) -> None:
    login(client, test_users.viewer_username, test_users.viewer_password)
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        assert db.scalar(select(func.count(AuditLog.id))) == 1
        assert db.scalar(select(func.count(UserSession.id))) == 1
