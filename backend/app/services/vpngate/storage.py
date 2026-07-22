import os
from pathlib import Path
import tempfile


class SecureConfigStore:
    def __init__(self, directory: str | Path) -> None:
        configured = Path(directory)
        if configured.exists() and configured.is_symlink():
            raise ValueError("OpenVPN config directory must not be a symbolic link")
        configured.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(configured, 0o700)
        self._directory = configured.resolve()

    @property
    def directory(self) -> Path:
        return self._directory

    def path_for(self, node_id: int) -> Path:
        if node_id <= 0:
            raise ValueError("node_id must be positive")
        return self._directory / f"node-{node_id}.ovpn"

    def write(self, node_id: int, config: str) -> Path:
        if not config or "\x00" in config:
            raise ValueError("config must be non-empty text")
        target = self.path_for(node_id)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".node-{node_id}-", suffix=".tmp", dir=self._directory
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
                file_descriptor = -1
                handle.write(config)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, target)
            os.chmod(target, 0o600)
        except Exception:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            temporary_path.unlink(missing_ok=True)
            raise
        return target
