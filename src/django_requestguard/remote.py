import json
import logging
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .config import get_setting
from .rules import activate_blocked_path_rules, validate_blocked_path_rules_payload


logger = logging.getLogger(__name__)


class RemoteRulesError(Exception):
    """Raised when remote blocked-path rules cannot be downloaded or parsed."""


def _positive_float_setting(name: str) -> float:
    try:
        value = float(get_setting(name))
    except (TypeError, ValueError) as exc:
        raise RemoteRulesError(f"{name} must be a number") from exc
    if value <= 0:
        raise RemoteRulesError(f"{name} must be greater than zero")
    return value


def _client_kwargs() -> dict[str, object]:
    kwargs = {
        "region_name": get_setting("BLOCKED_PATHS_AWS_REGION"),
        "config": Config(
            connect_timeout=_positive_float_setting(
                "BLOCKED_PATHS_CONNECT_TIMEOUT"
            ),
            read_timeout=_positive_float_setting("BLOCKED_PATHS_READ_TIMEOUT"),
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    }
    access_key = get_setting("BLOCKED_PATHS_AWS_ACCESS_KEY_ID")
    secret_key = get_setting("BLOCKED_PATHS_AWS_SECRET_ACCESS_KEY")
    session_token = get_setting("BLOCKED_PATHS_AWS_SESSION_TOKEN")

    if bool(access_key) != bool(secret_key):
        raise RemoteRulesError(
            "BLOCKED_PATHS_AWS_ACCESS_KEY_ID and "
            "BLOCKED_PATHS_AWS_SECRET_ACCESS_KEY must be configured together"
        )
    if session_token and not (access_key and secret_key):
        raise RemoteRulesError(
            "BLOCKED_PATHS_AWS_SESSION_TOKEN requires package-specific "
            "access and secret keys"
        )

    if access_key and secret_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key
        if session_token:
            kwargs["aws_session_token"] = session_token

    return {name: value for name, value in kwargs.items() if value}


def download_blocked_path_rules() -> tuple[bytes, object]:
    """Download and validate the configured S3 rules object."""
    bucket = get_setting("BLOCKED_PATHS_BUCKET")
    key = get_setting("BLOCKED_PATHS_KEY")
    if not bucket:
        raise RemoteRulesError("BLOCKED_PATHS_BUCKET is not configured")
    if not key:
        raise RemoteRulesError("BLOCKED_PATHS_KEY is not configured")

    try:
        max_bytes = int(get_setting("BLOCKED_PATHS_MAX_DOWNLOAD_BYTES"))
    except (TypeError, ValueError) as exc:
        raise RemoteRulesError(
            "BLOCKED_PATHS_MAX_DOWNLOAD_BYTES must be an integer"
        ) from exc
    if max_bytes < 1:
        raise RemoteRulesError(
            "BLOCKED_PATHS_MAX_DOWNLOAD_BYTES must be greater than zero"
        )

    try:
        response = boto3.client("s3", **_client_kwargs()).get_object(
            Bucket=bucket,
            Key=key,
        )
        body = response["Body"]
        content_length = response.get("ContentLength")
        if isinstance(content_length, int) and content_length > max_bytes:
            body.close()
            raise RemoteRulesError(
                "Blocked-path configuration exceeds maximum allowed size"
            )

        try:
            data = body.read(max_bytes + 1)
        finally:
            body.close()

        if len(data) > max_bytes:
            raise RemoteRulesError(
                "Blocked-path configuration exceeds maximum allowed size"
            )

        payload: Any = json.loads(data)
        validate_blocked_path_rules_payload(payload)
        return data, payload
    except RemoteRulesError:
        raise
    except (
        BotoCoreError,
        ClientError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise RemoteRulesError(str(exc)) from exc


def load_blocked_path_rules_from_s3() -> bool:
    """Load S3 rules into this process, retaining existing rules on failure."""
    if not get_setting("BLOCKED_PATHS_BUCKET"):
        logger.debug(
            "BLOCKED_PATHS_BUCKET is not configured; using existing rules"
        )
        return False

    try:
        _, payload = download_blocked_path_rules()
        new_rules = validate_blocked_path_rules_payload(payload)
        activate_blocked_path_rules(new_rules)
    except RemoteRulesError:
        logger.exception(
            "Unable to load blocked-path rules from S3; "
            "continuing with the existing rules"
        )
        return False

    logger.info(
        "Loaded blocked-path rules from S3: %d contains, %d starts-with",
        len(new_rules.contains),
        len(new_rules.starts_with),
    )
    return True
