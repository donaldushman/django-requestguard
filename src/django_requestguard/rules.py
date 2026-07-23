from dataclasses import dataclass
from threading import RLock

MAX_RULES_PER_TYPE = 10_000
MAX_PATTERN_LENGTH = 500
SUPPORTED_SCHEMA = 1

@dataclass(frozen=True)
class BlockedPathRules:
    contains: frozenset[str]
    starts_with: frozenset[str]
    exact_segments: frozenset[str]
    segment_prefixes: frozenset[str]


# These rules remain active even if the remote configuration cannot be loaded.
BUILT_IN_RULES = BlockedPathRules(
    contains=frozenset(),
    starts_with=frozenset(),
    exact_segments=frozenset({
        ".env",
        ".aws",
        ".ssh",
        ".htaccess",
        ".htpasswd",
        "manage.py",
        "settings.py",
    }),
    segment_prefixes=frozenset({
        ".env.",
    }),
)

_rules = BUILT_IN_RULES
_lock = RLock()


def get_blocked_path_rules() -> BlockedPathRules:
    """
    Return the currently active in-memory blocked-path rules.
    """
    return _rules


def activate_blocked_path_rules(rules: BlockedPathRules) -> None:
    """Atomically replace the active in-memory rules."""
    global _rules

    with _lock:
        _rules = rules


def _validate_string_rules(
    values: object,
    rule_type: str,
) -> frozenset[str]:
    """
    Validate and normalize a collection of string-based rules.
    """
    if not isinstance(values, list):
        raise ValueError(f"'rules.{rule_type}' must be a list")

    if len(values) > MAX_RULES_PER_TYPE:
        raise ValueError(
            f"'rules.{rule_type}' exceeds the maximum of "
            f"{MAX_RULES_PER_TYPE} rules"
        )

    validated: set[str] = set()

    for value in values:
        if not isinstance(value, str):
            raise ValueError(
                f"Every rule in 'rules.{rule_type}' must be a string"
            )

        value = value.strip().lower()

        if not value:
            continue

        if len(value) > MAX_PATTERN_LENGTH:
            raise ValueError(
                f"A rule in 'rules.{rule_type}' exceeds "
                f"{MAX_PATTERN_LENGTH} characters"
            )

        validated.add(value)

    return frozenset(validated)


def validate_blocked_path_rules_payload(payload: object) -> BlockedPathRules:
    """
    Validate payload shape and compile a complete BlockedPathRules object.
    """
    if not isinstance(payload, dict):
        raise ValueError("Configuration root must be a JSON object")

    schema = payload.get("schema")

    if schema != SUPPORTED_SCHEMA:
        raise ValueError(
            f"Unsupported schema version {schema!r}; "
            f"expected {SUPPORTED_SCHEMA}"
        )

    rules_payload = payload.get("rules")

    if not isinstance(rules_payload, dict):
        raise ValueError("'rules' must be an object")

    unsupported_rule_types = set(rules_payload) - {"contains", "starts_with"}
    if unsupported_rule_types:
        names = ", ".join(sorted(unsupported_rule_types))
        raise ValueError(f"Unsupported rule type(s): {names}")

    contains = _validate_string_rules(
        rules_payload.get("contains", []),
        "contains",
    )

    starts_with = _validate_string_rules(
        rules_payload.get("starts_with", []),
        "starts_with",
    )

    return BlockedPathRules(
        contains=BUILT_IN_RULES.contains | contains,
        starts_with=BUILT_IN_RULES.starts_with | starts_with,
        exact_segments=BUILT_IN_RULES.exact_segments,
        segment_prefixes=BUILT_IN_RULES.segment_prefixes,
    )
