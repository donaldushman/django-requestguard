import os
from typing import Any

from django.conf import settings as django_settings


DEFAULTS: dict[str, Any] = {
    "BLOCKED_PATHS_AWS_REGION": "us-east-2",
    "BLOCKED_PATHS_KEY": "django/security/blocked-paths.json",
    "BLOCKED_PATHS_MAX_DOWNLOAD_BYTES": 1024 * 1024,
    "BLOCKED_PATHS_CONNECT_TIMEOUT": 3,
    "BLOCKED_PATHS_READ_TIMEOUT": 5,
}


def get_setting(name: str, default: Any = None) -> Any:
    """Read a Django setting, falling back to an environment variable."""
    if hasattr(django_settings, name):
        return getattr(django_settings, name)

    return os.environ.get(name, DEFAULTS.get(name, default))
