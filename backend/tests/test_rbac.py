import secrets

from fastapi import FastAPI
from fastapi.testclient import TestClient

from conftest import UserCredentials, login


def test_super_admin_can_manage_users(
    client: TestClient, test_users: UserCredentials
) -> None:
    csrf = login(client, test_users.super_username, test_users.super_password)
    listed = client.get("/api/v1/users")
    assert listed.status_code == 200
    assert listed.json()["total"] == 3

    created = client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "new.viewer",
            "password": secrets.token_urlsafe(24),
            "role": "VIEWER",
        },
    )
    assert created.status_code == 201
    assert "password_hash" not in created.json()
    assert "password" not in created.text.lower()


def test_admin_and_viewer_cannot_manage_users(
    app: FastAPI, test_users: UserCredentials
) -> None:
    for username, password in (
        (test_users.admin_username, test_users.admin_password),
        (test_users.viewer_username, test_users.viewer_password),
    ):
        with TestClient(app) as client:
            login(client, username, password)
            assert client.get("/api/v1/users").status_code == 403


def test_last_super_admin_cannot_be_deactivated(
    client: TestClient, test_users: UserCredentials
) -> None:
    csrf = login(client, test_users.super_username, test_users.super_password)
    users = client.get("/api/v1/users").json()["items"]
    super_id = next(item["id"] for item in users if item["role"] == "SUPER_ADMIN")
    response = client.patch(
        f"/api/v1/users/{super_id}",
        headers={"X-CSRF-Token": csrf},
        json={"is_active": False},
    )
    assert response.status_code == 409


def test_super_admin_can_reset_password_without_exposing_it(
    app: FastAPI, test_users: UserCredentials
) -> None:
    replacement = secrets.token_urlsafe(24)
    with TestClient(app) as manager, TestClient(app) as active_user:
        csrf = login(manager, test_users.super_username, test_users.super_password)
        login(active_user, test_users.viewer_username, test_users.viewer_password)
        users = manager.get("/api/v1/users").json()["items"]
        viewer_id = next(
            item["id"] for item in users if item["username"] == test_users.viewer_username
        )

        reset = manager.post(
            f"/api/v1/users/{viewer_id}/password",
            headers={"X-CSRF-Token": csrf},
            json={"new_password": replacement},
        )
        assert reset.status_code == 204
        assert replacement not in reset.text
        assert active_user.get("/api/v1/auth/me").status_code == 401

        logs = manager.get("/api/v1/logs?source=audit")
        assert logs.status_code == 200
        assert replacement not in logs.text
        assert "user.password_reset" in logs.text

    with TestClient(app) as fresh:
        login(fresh, test_users.viewer_username, replacement)


def test_admin_cannot_reset_user_password(
    client: TestClient, test_users: UserCredentials
) -> None:
    csrf = login(client, test_users.admin_username, test_users.admin_password)
    response = client.post(
        "/api/v1/users/1/password",
        headers={"X-CSRF-Token": csrf},
        json={"new_password": secrets.token_urlsafe(24)},
    )
    assert response.status_code == 403
