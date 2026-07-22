import json
import logging
import re
from datetime import datetime, timezone
from typing import Any


_SENSITIVE_PATTERN = re.compile(
    r"(?i)(password|passwd|token|cookie|api[_-]?key|authorization|secret)"
)
_SENSITIVE_TEXT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|token|cookie|api[_-]?key|authorization|secret)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_SENSITIVE_HEADER_PATTERN = re.compile(
    r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]*"
)
REDACTED = "[REDACTED]"


def redact(value: Any, key: str = "") -> Any:
    if key and _SENSITIVE_PATTERN.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


def redact_text(value: str) -> str:
    without_headers = _SENSITIVE_HEADER_PATTERN.sub(
        lambda matched: f"{matched.group(1)}: {REDACTED}", value
    )
    return _SENSITIVE_TEXT_PATTERN.sub(
        lambda matched: f"{matched.group(1)}{matched.group(2)}{REDACTED}", without_headers
    )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload["fields"] = redact(fields)
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
