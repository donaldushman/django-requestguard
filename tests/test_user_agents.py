import pytest
from django.test import Client, override_settings

from django_requestguard.user_agents import (
    DEFAULT_BLOCKED_USER_AGENTS,
    matched_user_agent,
)


@pytest.mark.parametrize("agent", sorted(DEFAULT_BLOCKED_USER_AGENTS))
@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_default_crawlers_blocked(agent):
    assert Client().get("/home", HTTP_USER_AGENT=f"Mozilla/5.0 {agent.upper()}").status_code == 403


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=False)
def test_disabled_by_default_even_for_known_crawler():
    assert Client().get("/home", HTTP_USER_AGENT="Bytespider").status_code == 200


@pytest.mark.parametrize("agent", [
    "Googlebot/2.1",
    "bingbot/2.0",
    "Mozilla/5.0 Firefox/128.0",
    "",
])
@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_legitimate_agents_allowed(agent):
    assert Client().get("/home", HTTP_USER_AGENT=agent).status_code == 200


@override_settings(
    REQUESTGUARD_BLOCK_USER_AGENTS=True,
    REQUESTGUARD_EXTRA_BLOCKED_USER_AGENTS=["CustomCrawler"],
)
def test_additional_pattern_is_case_insensitive():
    assert Client().get("/home", HTTP_USER_AGENT="customcrawler/1.0").status_code == 403


@override_settings(
    REQUESTGUARD_BLOCK_USER_AGENTS=True,
    REQUESTGUARD_ALLOWED_USER_AGENTS=["Bytespider"],
)
def test_excluded_pattern_is_allowed():
    assert Client().get("/home", HTTP_USER_AGENT="Bytespider").status_code == 200


@override_settings(
    REQUESTGUARD_BLOCK_USER_AGENTS=True,
    REQUESTGUARD_ALLOWED_USER_AGENTS=["Bytespider"],
)
def test_exclusion_does_not_bypass_sensitive_paths():
    assert Client().get("/.env", HTTP_USER_AGENT="Bytespider").status_code == 404


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_path_blocking_precedes_user_agent_filtering():
    assert Client().get("/.env", HTTP_USER_AGENT="Bytespider").status_code == 404


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True)
def test_match_returns_identifying_pattern():
    assert matched_user_agent("Example Bytespider/1.0") == "bytespider"


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS="false")
def test_string_false_is_not_truthy():
    assert matched_user_agent("Bytespider") is None


@override_settings(REQUESTGUARD_BLOCK_USER_AGENTS=True, REQUESTGUARD_EXTRA_BLOCKED_USER_AGENTS="crawler")
def test_rejects_string_instead_of_pattern_collection():
    with pytest.raises(ValueError, match="collection"):
        matched_user_agent("Bytespider")
