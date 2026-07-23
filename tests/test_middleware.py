import pytest
from django.http import HttpResponse
from django.test import Client

from django_requestguard import middleware
from django_requestguard import rules


@pytest.mark.django_db
def test_allows_path_that_does_not_match_rules():
    client = Client()
    response = client.get("/home")
    assert response.status_code == 200


@pytest.mark.django_db
def test_blocks_builtin_contains_rule():
    client = Client()
    response = client.get("/.env")
    assert response.status_code == 404


@pytest.mark.django_db
def test_blocks_builtin_starts_with_rule():
    client = Client()
    response = client.get("/manage.py")
    assert response.status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/config/.env.production",
        "/private/.ssh/id_rsa",
        "/nested/.aws/credentials",
        "/admin/settings.py/backup",
    ],
)
def test_blocks_complete_sensitive_path_segments(path):
    response = Client().get(path)

    assert response.status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/docs/environment",
        "/assets/foo.envoy.js",
        "/manage.py-docs",
        "/settings.py.example",
        "/profiles/.ssh-key",
    ],
)
def test_allows_names_that_only_partially_match_builtin_rules(path):
    response = Client().get(path)

    assert response.status_code == 200


@pytest.mark.django_db
def test_loads_remote_rules_when_middleware_starts(monkeypatch):
    loaded = False

    def load_rules():
        nonlocal loaded
        loaded = True
        return True

    monkeypatch.setattr(middleware, "load_blocked_path_rules_from_s3", load_rules)

    middleware.BlockBotsMiddleware(lambda request: HttpResponse())

    assert loaded is True
