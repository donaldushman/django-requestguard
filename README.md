# django-requestguard

`django-requestguard` is a reusable Django middleware package that blocks common scanner/bot requests for sensitive paths.

It provides:
- built-in blocked path protections (for example `/.env`, `/.ssh`, `/manage.py`)
- support for additional JSON-driven rules (`contains`, `starts_with`)
- automatic rule loading from S3 when each web process starts

## Installation

```bash
pip install django-requestguard
```

For local development in this repository:

```bash
pip install -e .[dev]
```

## Django Configuration

Add the app and middleware:

```python
INSTALLED_APPS = [
    # ...
    "django_requestguard",
]

MIDDLEWARE = [
    # ...
        "django_requestguard.middleware.BlockBotsMiddleware",
]
```

## Configuration

This package reads configuration from environment variables:

```python
# Required for loading rules from S3
BLOCKED_PATHS_BUCKET=my-security-configs

# Optional (default shown)
BLOCKED_PATHS_KEY=django/security/blocked-paths.json
BLOCKED_PATHS_AWS_REGION=us-east-2
BLOCKED_PATHS_CONNECT_TIMEOUT=3
BLOCKED_PATHS_READ_TIMEOUT=5

# Optional explicit credentials; if omitted boto3 default chain is used.
BLOCKED_PATHS_AWS_ACCESS_KEY_ID=...
BLOCKED_PATHS_AWS_SECRET_ACCESS_KEY=...
BLOCKED_PATHS_AWS_SESSION_TOKEN=...
```

If you deploy on Heroku, set these via config vars.

## Rule Loading

The middleware downloads and validates the configured rules when each web
process starts. If S3 is unavailable or the object is invalid, the process
continues using the built-in rules. With Gunicorn, `--preload` loads the rules
once before worker processes are forked; without it, each worker loads its own
copy at startup.

Rules JSON uses this shape:

```json
{
    "schema": 1,
    "rules": {
        "contains": ["/.git/", ".sql"],
        "starts_with": ["/private/"]
    }
}
```

## Default Behavior

If no custom settings are provided:
- built-in path block rules are active
- additional remote rules are optional


## Optional user-agent filtering

User-agent filtering is **disabled by default**, so upgrading does not change
existing request behavior. To enable it:

```python
REQUESTGUARD_BLOCK_USER_AGENTS = True
```

The package includes a small curated list of unwanted crawler identifiers:
`Bytespider`, `SemrushBot`, `ExaSearchBot`, `SEOJuice-SearchBot`,
`RecordedFuture Global Inventory Crawler`, and `RealCyber-enricher`.
Matching is case-insensitive and uses substrings of the user-agent header.
User-agent headers are self-reported and are not proof of crawler identity.

Optionally add patterns or exclude individual patterns:

```python
REQUESTGUARD_EXTRA_BLOCKED_USER_AGENTS = ["MyUnwantedCrawler"]
REQUESTGUARD_ALLOWED_USER_AGENTS = ["semrushbot"]
```

The allowed list removes exact patterns from the combined blocklist; it does
**not** bypass sensitive-path rules or act as a trusted-user-agent allowlist.
Blocked user agents receive HTTP 403; existing path rules continue to return
HTTP 404. No remote service or database lookup is required for user-agent checks.

Place `django_requestguard.middleware.BlockBotsMiddleware` near the beginning
of `MIDDLEWARE`, ideally before session and authentication middleware, to
reject unwanted requests before downstream application processing.

## Running Tests

```bash
pytest
```

## License

MIT
