import logging

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from django_requestguard.middleware import BlockBotsMiddleware


@pytest.fixture
def middleware(monkeypatch):
    # Avoid remote startup calls: these tests exercise request-time logging.
    monkeypatch.setattr(
        "django_requestguard.middleware.load_blocked_path_rules_from_s3",
        lambda: None,
    )
    return BlockBotsMiddleware(lambda request: HttpResponse("ok"))


def records(caplog):
    return [record for record in caplog.records if record.name == "django_requestguard"]


def test_logs_blocked_builtin_path(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="django_requestguard"):
        response = middleware(RequestFactory().get("/.env?token=secret"))

    assert response.status_code == 404
    entries = records(caplog)
    assert len(entries) == 1
    record = entries[0]
    assert record.requestguard_reason == "blocked_path"
    assert record.requestguard_rule == ".env"
    assert record.requestguard_path == "/.env"
    assert record.requestguard_status == 404
    assert "token=secret" not in record.getMessage()


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_logs_blocked_user_agent_without_full_header(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="django_requestguard"):
        response = middleware(
            RequestFactory().get(
                "/events/?password=secret",
                HTTP_USER_AGENT="Mozilla/5.0 Bytespider/1.0 private-identifier",
                REMOTE_ADDR="192.0.2.100",
            )
        )

    assert response.status_code == 403
    entries = records(caplog)
    assert len(entries) == 1
    record = entries[0]
    assert record.requestguard_reason == "blocked_user_agent"
    assert record.requestguard_rule == "bytespider"
    assert record.requestguard_path == "/events/"
    assert record.requestguard_status == 403
    assert "password=secret" not in record.getMessage()
    assert "private-identifier" not in record.getMessage()
    assert "192.0.2.100" not in record.getMessage()


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_path_block_takes_priority_and_logs_once(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="django_requestguard"):
        response = middleware(
            RequestFactory().get("/.env", HTTP_USER_AGENT="Bytespider")
        )
    assert response.status_code == 404
    assert len(records(caplog)) == 1
    assert records(caplog)[0].requestguard_reason == "blocked_path"


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_does_not_log_allowed_request(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="django_requestguard"):
        response = middleware(
            RequestFactory().get("/home", HTTP_USER_AGENT="Googlebot/2.1")
        )
    assert response.status_code == 200
    assert records(caplog) == []


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=False)
def test_does_not_log_user_agent_when_filter_disabled(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="django_requestguard"):
        response = middleware(
            RequestFactory().get("/home", HTTP_USER_AGENT="Bytespider")
        )
    assert response.status_code == 200
    assert records(caplog) == []


def test_logs_each_remote_path_rule_type(middleware, monkeypatch, caplog):
    from django_requestguard.rules import BlockedPathRules

    custom_rules = BlockedPathRules(
        contains=frozenset({"/.git/"}),
        starts_with=frozenset({"/private/"}),
        exact_segments=frozenset(),
        segment_prefixes=frozenset(),
    )
    monkeypatch.setattr(
        "django_requestguard.middleware.get_blocked_path_rules",
        lambda: custom_rules,
    )
    with caplog.at_level(logging.INFO, logger="django_requestguard"):
        first = middleware(RequestFactory().get("/foo/.git/config"))
        second = middleware(RequestFactory().get("/private/file"))

    assert first.status_code == second.status_code == 404
    assert [r.requestguard_rule for r in records(caplog)] == [
        "/.git/",
        "/private/",
    ]
