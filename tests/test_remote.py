import io
import json

import pytest
from django.test import override_settings

from django_requestguard import remote, rules


class FakeBody(io.BytesIO):
    read_called = False

    def read(self, *args, **kwargs):
        self.read_called = True
        return super().read(*args, **kwargs)


@pytest.fixture(autouse=True)
def restore_rules(monkeypatch):
    monkeypatch.setattr(rules, "_rules", rules.BUILT_IN_RULES)


def _s3_response(payload):
    data = json.dumps(payload).encode()
    return {
        "Body": FakeBody(data),
        "ContentLength": len(data),
    }


@override_settings(
    BLOCKED_PATHS_BUCKET="rules-bucket",
    BLOCKED_PATHS_KEY="rules.json",
)
def test_loads_s3_rules_at_process_startup(monkeypatch):
    monkeypatch.setattr(rules, "_rules", rules.BUILT_IN_RULES)
    payload = {
        "schema": 1,
        "rules": {
            "contains": ["secret-file"],
            "starts_with": [],
        },
    }
    s3 = type(
        "FakeS3",
        (),
        {"get_object": lambda self, **kwargs: _s3_response(payload)},
    )()
    monkeypatch.setattr(remote.boto3, "client", lambda *args, **kwargs: s3)

    assert remote.load_blocked_path_rules_from_s3() is True
    assert "secret-file" in rules.get_blocked_path_rules().contains


@override_settings(BLOCKED_PATHS_BUCKET="rules-bucket")
def test_keeps_existing_rules_when_s3_load_fails(monkeypatch):
    monkeypatch.setattr(rules, "_rules", rules.BUILT_IN_RULES)
    existing = rules.get_blocked_path_rules()
    monkeypatch.setattr(
        remote,
        "download_blocked_path_rules",
        lambda: (_ for _ in ()).throw(remote.RemoteRulesError("unavailable")),
    )

    assert remote.load_blocked_path_rules_from_s3() is False
    assert rules.get_blocked_path_rules() is existing


def test_skips_s3_when_bucket_is_not_configured(monkeypatch):
    called = False

    def client(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(remote.boto3, "client", client)

    assert remote.load_blocked_path_rules_from_s3() is False
    assert called is False


@override_settings(
    BLOCKED_PATHS_BUCKET="rules-bucket",
    BLOCKED_PATHS_MAX_DOWNLOAD_BYTES=10,
)
def test_rejects_oversized_s3_object_before_reading(monkeypatch):
    body = FakeBody(b"{}")
    s3 = type(
        "FakeS3",
        (),
        {
            "get_object": lambda self, **kwargs: {
                "Body": body,
                "ContentLength": 11,
            }
        },
    )()
    monkeypatch.setattr(remote.boto3, "client", lambda *args, **kwargs: s3)

    try:
        remote.download_blocked_path_rules()
    except remote.RemoteRulesError:
        pass
    else:
        raise AssertionError("Expected an oversized object to be rejected")

    assert body.read_called is False
    assert body.closed is True


@override_settings(
    BLOCKED_PATHS_AWS_ACCESS_KEY_ID="access-key",
    BLOCKED_PATHS_AWS_SECRET_ACCESS_KEY=None,
    BLOCKED_PATHS_AWS_SESSION_TOKEN=None,
)
def test_rejects_incomplete_package_specific_credentials():
    with pytest.raises(remote.RemoteRulesError, match="must be configured together"):
        remote._client_kwargs()


def test_rejects_removed_regex_rule_type():
    payload = {
        "schema": 1,
        "rules": {
            "contains": [],
            "starts_with": [],
            "regex": [".*"],
        },
    }

    with pytest.raises(ValueError, match="Unsupported rule type.*regex"):
        rules.validate_blocked_path_rules_payload(payload)
