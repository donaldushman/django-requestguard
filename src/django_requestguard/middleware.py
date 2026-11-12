"""Request filtering middleware with minimal blocked-request diagnostics."""

import logging

from django.http import HttpResponseForbidden, HttpResponseNotFound

from .rules import get_blocked_path_rules
from .remote import load_blocked_path_rules_from_s3
from .user_agents import matched_user_agent


logger = logging.getLogger("django_requestguard")


def _blocked(request, reason, rule, status):
    # Do not include query strings, IP addresses, or complete user agents.
    # LogRecord extras allow structured formatters to use these fields.
    logger.info(
        "blocked_request reason=%s path=%s rule=%s status=%s",
        reason,
        request.path,
        rule,
        status,
        extra={
            "requestguard_reason": reason,
            "requestguard_path": request.path,
            "requestguard_rule": rule,
            "requestguard_status": status,
        },
    )
    if status == 403:
        return HttpResponseForbidden()
    return HttpResponseNotFound()


class BlockBotsMiddleware:
    """
    Block common scanner requests for sensitive files and paths, and
    optionally reject selected crawler user agents.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        load_blocked_path_rules_from_s3()

    def __call__(self, request):
        path = request.path.lower()
        rules = get_blocked_path_rules()
        segments = path.split("/")

        for segment in segments:
            if segment in rules.exact_segments:
                return _blocked(request, "blocked_path", segment, 404)

        for segment in segments:
            for prefix in rules.segment_prefixes:
                if segment.startswith(prefix):
                    return _blocked(request, "blocked_path", prefix, 404)

        for pattern in rules.contains:
            if pattern in path:
                return _blocked(request, "blocked_path", pattern, 404)

        for pattern in rules.starts_with:
            if path.startswith(pattern):
                return _blocked(request, "blocked_path", pattern, 404)

        agent_pattern = matched_user_agent(request.META.get("HTTP_USER_AGENT", ""))
        if agent_pattern:
            return _blocked(request, "blocked_user_agent", agent_pattern, 403)

        return self.get_response(request)
