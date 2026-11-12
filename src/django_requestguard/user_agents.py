"""Opt-in filtering of self-identified crawler user agents."""

from .config import get_setting

DEFAULT_BLOCKED_USER_AGENTS = frozenset({
    "bytespider",
    "semrushbot",
    "exasearchbot",
    "seojuice-searchbot",
    "recordedfuture global inventory crawler",
    "realcyber-enricher",
})


def _patterns(setting_name):
    value = get_setting(setting_name, [])
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{setting_name} must be a collection of strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{setting_name} must contain only strings")
    return frozenset(item.strip().lower() for item in value if item.strip())


def user_agent_filter_enabled():
    value = get_setting("REQUESTGUARD_BLOCK_USER_AGENTS", False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    raise ValueError("REQUESTGUARD_BLOCK_USER_AGENTS must be a boolean")


def matched_user_agent(user_agent):
    """Return the matching blocked pattern, or None.

    Exclusions remove individual blocked patterns; they do not grant
    blanket permission to bypass other rules.
    """
    if not user_agent_filter_enabled():
        return None
    excluded = _patterns("REQUESTGUARD_ALLOWED_USER_AGENTS")
    additional = _patterns("REQUESTGUARD_EXTRA_BLOCKED_USER_AGENTS")
    patterns = (DEFAULT_BLOCKED_USER_AGENTS | additional) - excluded
    normalized = user_agent.lower()
    return next((pattern for pattern in sorted(patterns) if pattern in normalized), None)
