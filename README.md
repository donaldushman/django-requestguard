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

## Running Tests

```bash
pytest
```

## License

MIT
