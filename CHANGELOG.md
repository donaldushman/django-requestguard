# Changelog

## v0.2.0 (unreleased)

- Add opt-in, case-insensitive user-agent filtering, disabled by default.
- Include a curated set of unwanted crawler identifiers, with settings to add
  or exclude individual blocked patterns.
- Return HTTP 403 for blocked user agents; retain HTTP 404 for blocked paths.
- Log blocked requests at INFO level with the matched rule, reason, path,
  and status, using the `django_requestguard` logger.
- Avoid logging query strings, IP addresses, and complete user-agent headers.
- Add tests and documentation for user-agent filtering and logging.

## v0.1.0

- Initial project version (not published to PyPI).
- Built-in protection against common scanner paths.
- Optional remote S3 path-rule management with validation and atomic loading.
- Automated test coverage.
