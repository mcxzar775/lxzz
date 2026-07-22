#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
from typing import Any, Sequence


VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.+-][0-9A-Za-z.-]+)?$")
PYPROJECT_VERSION_PATTERN = re.compile(
    r'^version = "([0-9][0-9A-Za-z.+-]*)"$', re.MULTILINE
)
RUNTIME_VERSION_PATTERN = re.compile(
    r'^__version__ = "([0-9][0-9A-Za-z.+-]*)"$', re.MULTILINE
)
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024

REQUIRED_FILES = (
    ".env.example",
    ".gitignore",
    "Makefile",
    "README.md",
    "backend/README.md",
    "backend/alembic.ini",
    "backend/pyproject.toml",
    "backend/uv.lock",
    "frontend/index.html",
    "frontend/package.json",
    "frontend/pnpm-lock.yaml",
    "frontend/pnpm-workspace.yaml",
    "frontend/tsconfig.json",
    "frontend/vite.config.ts",
    "frontend/dist/index.html",
)
OPTIONAL_FILES = (
    "CHANGELOG.md",
    "SECURITY.md",
)
SOURCE_DIRECTORIES = (
    "backend/alembic",
    "backend/app",
    "backend/tests",
    "deploy",
    "docs",
    "frontend/dist",
    "frontend/src",
    "scripts",
    "tools",
)
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}
EXCLUDED_NAMES = {
    ".env",
    "credential.key",
}
EXCLUDED_SUFFIXES = {
    ".db",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
}


class ReleaseArchiveError(RuntimeError):
    pass


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_version(root: Path) -> str:
    pyproject = (root / "backend/pyproject.toml").read_text(encoding="utf-8")
    runtime = (root / "backend/app/__init__.py").read_text(encoding="utf-8")
    project_match = PYPROJECT_VERSION_PATTERN.search(pyproject)
    runtime_match = RUNTIME_VERSION_PATTERN.search(runtime)
    if project_match is None or runtime_match is None:
        raise ReleaseArchiveError("project version is missing")
    project_version = project_match.group(1)
    if not VERSION_PATTERN.fullmatch(project_version):
        raise ReleaseArchiveError("project version is invalid")
    if runtime_match.group(1) != project_version:
        raise ReleaseArchiveError("pyproject and runtime versions do not match")
    return project_version


def _is_excluded(relative: Path) -> bool:
    return (
        any(part in EXCLUDED_PARTS for part in relative.parts)
        or relative.name in EXCLUDED_NAMES
        or relative.suffix.lower() in EXCLUDED_SUFFIXES
        or relative.name == ".DS_Store"
    )


def _source_files(root: Path) -> list[Path]:
    files: set[Path] = set()
    for relative_text in REQUIRED_FILES:
        relative = Path(relative_text)
        source = root / relative
        if not source.is_file() or source.is_symlink():
            raise ReleaseArchiveError(f"required release file is missing or unsafe: {relative}")
        files.add(relative)
    for relative_text in OPTIONAL_FILES:
        relative = Path(relative_text)
        source = root / relative
        if source.is_file() and not source.is_symlink():
            files.add(relative)
    for directory_text in SOURCE_DIRECTORIES:
        directory = root / directory_text
        if not directory.is_dir() or directory.is_symlink():
            if directory_text == "docs":
                continue
            raise ReleaseArchiveError(
                f"required release directory is missing or unsafe: {directory_text}"
            )
        for source in directory.rglob("*"):
            relative = source.relative_to(root)
            if _is_excluded(relative):
                continue
            if source.is_symlink():
                raise ReleaseArchiveError(f"release source contains a symlink: {relative}")
            if source.is_file():
                files.add(relative)
    return sorted(files, key=lambda value: value.as_posix())


def _tar_info(name: str, *, size: int, mode: int, epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def _add_bytes(
    archive: tarfile.TarFile,
    name: str,
    payload: bytes,
    *,
    mode: int,
    epoch: int,
) -> None:
    from io import BytesIO

    archive.addfile(
        _tar_info(name, size=len(payload), mode=mode, epoch=epoch),
        BytesIO(payload),
    )


def _file_mode(relative: Path) -> int:
    return 0o755 if relative.suffix == ".sh" or relative == Path("tools/release_archive.py") else 0o644


def _manifest_entry(relative: Path, payload: bytes) -> dict[str, object]:
    return {
        "path": relative.as_posix(),
        "sha256": _sha256_bytes(payload),
        "size": len(payload),
    }


def build_archive(root: Path, output_directory: Path, epoch: int) -> Path:
    root = root.resolve()
    if not root.is_dir():
        raise ReleaseArchiveError("project root is missing")
    if epoch < 0 or epoch > 4_294_967_295:
        raise ReleaseArchiveError("SOURCE_DATE_EPOCH is out of range")
    version = _project_version(root)
    files = _source_files(root)
    prefix = f"vpngate-manager-{version}"
    version_payload = f"{version}\n".encode()
    entries: list[dict[str, object]] = []
    payloads: list[tuple[Path, bytes]] = []
    for relative in files:
        payload = (root / relative).read_bytes()
        payloads.append((relative, payload))
        entries.append(_manifest_entry(relative, payload))
    entries.append(_manifest_entry(Path("VERSION"), version_payload))
    entries.sort(key=lambda item: str(item["path"]))
    manifest_payload = (
        json.dumps(
            {
                "format": 1,
                "source_date_epoch": epoch,
                "version": version,
                "files": entries,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()

    output_directory.mkdir(parents=True, exist_ok=True)
    if output_directory.is_symlink():
        raise ReleaseArchiveError("release output directory must not be a symlink")
    archive_path = output_directory / f"{prefix}.tar.gz"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{prefix}.",
            suffix=".tmp",
            dir=output_directory,
            delete=False,
        ) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw,
                mtime=epoch,
            ) as compressed:
                with tarfile.open(
                    mode="w",
                    fileobj=compressed,
                    format=tarfile.PAX_FORMAT,
                ) as archive:
                    for relative, payload in payloads:
                        _add_bytes(
                            archive,
                            f"{prefix}/{relative.as_posix()}",
                            payload,
                            mode=_file_mode(relative),
                            epoch=epoch,
                        )
                    _add_bytes(
                        archive,
                        f"{prefix}/VERSION",
                        version_payload,
                        mode=0o644,
                        epoch=epoch,
                    )
                    _add_bytes(
                        archive,
                        f"{prefix}/RELEASE-MANIFEST.json",
                        manifest_payload,
                        mode=0o644,
                        epoch=epoch,
                    )
        os.replace(temporary, archive_path)
        archive_path.chmod(0o644)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    checksum = _sha256_file(archive_path)
    checksum_path = archive_path.with_name(f"{archive_path.name}.sha256")
    if checksum_path.is_symlink():
        raise ReleaseArchiveError("checksum path must not be a symlink")
    checksum_path.write_text(f"{checksum}  {archive_path.name}\n", encoding="ascii")
    checksum_path.chmod(0o644)
    verify_archive(archive_path)
    return archive_path


def _safe_member_name(name: str) -> PurePosixPath:
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise ReleaseArchiveError("archive contains an unsafe path")
    if any(part in {"", "."} for part in candidate.parts):
        raise ReleaseArchiveError("archive contains a non-canonical path")
    return candidate


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    handle = archive.extractfile(member)
    if handle is None:
        raise ReleaseArchiveError("archive member cannot be read")
    payload = handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
    if len(payload) > MAX_ARCHIVE_MEMBER_BYTES:
        raise ReleaseArchiveError("archive member exceeds the size limit")
    return payload


def _manifest_files(payload: bytes) -> tuple[str, list[dict[str, Any]]]:
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseArchiveError("release manifest is invalid") from exc
    if not isinstance(parsed, dict) or parsed.get("format") != 1:
        raise ReleaseArchiveError("release manifest format is unsupported")
    version = parsed.get("version")
    files = parsed.get("files")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ReleaseArchiveError("release manifest version is invalid")
    if not isinstance(files, list) or not all(isinstance(item, dict) for item in files):
        raise ReleaseArchiveError("release manifest files are invalid")
    return version, files


def _verify_checksum_file(archive_path: Path) -> None:
    checksum_path = archive_path.with_name(f"{archive_path.name}.sha256")
    if not checksum_path.exists():
        return
    if checksum_path.is_symlink() or not checksum_path.is_file():
        raise ReleaseArchiveError("checksum file is unsafe")
    fields = checksum_path.read_text(encoding="ascii").strip().split()
    if len(fields) != 2 or fields[1] != archive_path.name:
        raise ReleaseArchiveError("checksum file is invalid")
    if fields[0] != _sha256_file(archive_path):
        raise ReleaseArchiveError("archive checksum does not match")


def verify_archive(archive_path: Path) -> str:
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ReleaseArchiveError("release archive is missing or unsafe")
    _verify_checksum_file(archive_path)
    members: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
    total_size = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            name = _safe_member_name(member.name).as_posix()
            if name in members:
                raise ReleaseArchiveError("archive contains a duplicate member")
            if not member.isfile():
                raise ReleaseArchiveError("archive contains a non-regular member")
            if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ReleaseArchiveError("archive member size is invalid")
            total_size += member.size
            if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                raise ReleaseArchiveError("archive exceeds the total size limit")
            members[name] = (member, _member_bytes(archive, member))

    prefixes = {PurePosixPath(name).parts[0] for name in members}
    if len(prefixes) != 1:
        raise ReleaseArchiveError("archive must contain one top-level directory")
    prefix = next(iter(prefixes))
    manifest_name = f"{prefix}/RELEASE-MANIFEST.json"
    if manifest_name not in members:
        raise ReleaseArchiveError("release manifest is missing")
    version, entries = _manifest_files(members[manifest_name][1])
    if prefix != f"vpngate-manager-{version}":
        raise ReleaseArchiveError("archive prefix does not match its version")

    expected_names = {manifest_name}
    seen_paths: set[str] = set()
    for entry in entries:
        path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or size < 0
        ):
            raise ReleaseArchiveError("release manifest entry is invalid")
        canonical = _safe_member_name(path).as_posix()
        if canonical != path or path in seen_paths:
            raise ReleaseArchiveError("release manifest path is invalid or duplicated")
        seen_paths.add(path)
        member_name = f"{prefix}/{path}"
        expected_names.add(member_name)
        manifest_member_record = members.get(member_name)
        if manifest_member_record is None:
            raise ReleaseArchiveError("manifest references a missing member")
        payload = manifest_member_record[1]
        if len(payload) != size or _sha256_bytes(payload) != digest:
            raise ReleaseArchiveError("release member does not match its manifest")
    if set(members) != expected_names:
        raise ReleaseArchiveError("archive contains files not covered by its manifest")
    if members[f"{prefix}/VERSION"][1] != f"{version}\n".encode():
        raise ReleaseArchiveError("VERSION does not match the release manifest")
    return version


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify a VPNGate release archive")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--root", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    verify = subparsers.add_parser("verify")
    verify.add_argument("archive", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        if arguments.command == "build":
            archive = build_archive(
                arguments.root,
                arguments.output_dir,
                arguments.source_date_epoch,
            )
            print(f"release archive: {archive}")
            print(f"sha256: {archive}.sha256")
        else:
            version = verify_archive(arguments.archive)
            print(f"release verified: {version}")
    except (OSError, ReleaseArchiveError, tarfile.TarError) as exc:
        print(f"release error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
