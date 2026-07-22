import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
from typing import Any


def _build_release(project_root: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(project_root / "tools/release_archive.py"),
            "build",
            "--root",
            str(project_root),
            "--output-dir",
            str(output),
            "--source-date-epoch",
            "1700000000",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_release_archive_is_reproducible_manifested_and_secret_free(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"

    first = _build_release(project_root, first_output)
    second = _build_release(project_root, second_output)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    first_archive = next(first_output.glob("vpngate-manager-*.tar.gz"))
    second_archive = second_output / first_archive.name
    assert first_archive.read_bytes() == second_archive.read_bytes()

    checksum_file = first_archive.with_name(f"{first_archive.name}.sha256")
    expected_checksum, expected_name = checksum_file.read_text(encoding="ascii").split()
    assert expected_name == first_archive.name
    assert hashlib.sha256(first_archive.read_bytes()).hexdigest() == expected_checksum

    with tarfile.open(first_archive, mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        assert all(member.isfile() for member in members)
        assert len(names) == len(set(names))
        assert all(".." not in PurePosixPath(name).parts for name in names)
        assert not any("credential.key" in name for name in names)
        assert not any("/data/" in name for name in names)
        assert not any("/.env" == name[-5:] for name in names)
        assert not any(name.endswith((".db", ".sqlite", ".sqlite3")) for name in names)
        prefix = PurePosixPath(names[0]).parts[0]
        required = {
            f"{prefix}/.gitignore",
            f"{prefix}/VERSION",
            f"{prefix}/RELEASE-MANIFEST.json",
            f"{prefix}/docs/GITHUB.md",
            f"{prefix}/scripts/install.sh",
            f"{prefix}/scripts/install-from-github.sh",
            f"{prefix}/scripts/diagnose.sh",
            f"{prefix}/scripts/uninstall.sh",
            f"{prefix}/backend/app/main.py",
            f"{prefix}/frontend/dist/index.html",
        }
        assert required.issubset(set(names))
        manifest_member = archive.getmember(f"{prefix}/RELEASE-MANIFEST.json")
        manifest_file = archive.extractfile(manifest_member)
        assert manifest_file is not None
        manifest: dict[str, Any] = json.loads(manifest_file.read())
        assert manifest["format"] == 1
        assert manifest["version"] == "0.1.1"
        covered = {f"{prefix}/{item['path']}" for item in manifest["files"]}
        assert set(names) == covered | {f"{prefix}/RELEASE-MANIFEST.json"}


def test_release_verifier_rejects_archive_path_traversal(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    archive_path = tmp_path / "malicious.tar.gz"
    payload_path = tmp_path / "payload"
    payload_path.write_text("unsafe", encoding="utf-8")
    with tarfile.open(archive_path, mode="w:gz") as archive:
        archive.add(payload_path, arcname="../outside")

    result = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools/release_archive.py"),
            "verify",
            str(archive_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 1
    assert "unsafe path" in result.stderr


def test_github_bootstrap_verifies_release_before_extracting_or_installing() -> None:
    project_root = Path(__file__).resolve().parents[2]
    installer = (project_root / "scripts/install-from-github.sh").read_text(
        encoding="utf-8"
    )

    assert "--repo OWNER/REPOSITORY" in installer
    assert "releases/download/v${INSTALL_VERSION}" in installer
    assert "raw.githubusercontent.com/${GITHUB_REPOSITORY}/v${INSTALL_VERSION}" in installer
    assert 'python3 "$verifier" verify "$archive"' in installer
    assert installer.index('python3 "$verifier" verify "$archive"') < installer.index(
        'tar -xzf "$archive"'
    )
    assert installer.index('tar -xzf "$archive"') < installer.index(
        'bash "${project_directory}/scripts/install.sh"'
    )
    assert "VPNGATE_ENABLE_REAL_NETWORK=true" not in installer
    assert "eval " not in installer
    assert "source " not in installer


def test_github_bootstrap_collects_credentials_and_uses_prebuilt_frontend() -> None:
    project_root = Path(__file__).resolve().parents[2]
    installer = (project_root / "scripts/install-from-github.sh").read_text(
        encoding="utf-8"
    )

    assert "prepare_bootstrap_credentials" in installer
    assert "Administrator password (at least 12 characters)" in installer
    assert 'VPNGATE_ADMIN_USERNAME="${VPNGATE_ADMIN_USERNAME:-admin}"' in installer
    assert 'VPNGATE_USE_PREBUILT_FRONTEND="${VPNGATE_USE_PREBUILT_FRONTEND:-true}"' in installer
    assert "export VPNGATE_ADMIN_PASSWORD" in installer
    assert 'printf \'%s\' "$VPNGATE_ADMIN_PASSWORD"' not in installer
