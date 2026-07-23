SECRET_KEY = "test-secret-key"
DEBUG = True
ROOT_URLCONF = "tests.urls"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django_requestguard",
]

MIDDLEWARE = [
    "django_requestguard.middleware.BlockBotsMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

USE_TZ = True
