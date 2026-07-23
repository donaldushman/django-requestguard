from django.http import HttpResponseNotFound

from .rules import get_blocked_path_rules
from .remote import load_blocked_path_rules_from_s3


class BlockBotsMiddleware:
    """
    Block common scanner requests for sensitive files and paths.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        load_blocked_path_rules_from_s3()

    def __call__(self, request):
        path = request.path.lower()
        rules = get_blocked_path_rules()
        segments = path.split("/")

        if any(segment in rules.exact_segments for segment in segments):
            return HttpResponseNotFound()

        if any(
            segment.startswith(prefix)
            for segment in segments
            for prefix in rules.segment_prefixes
        ):
            return HttpResponseNotFound()

        if any(pattern in path for pattern in rules.contains):
            return HttpResponseNotFound()

        if any(path.startswith(pattern) for pattern in rules.starts_with):
            return HttpResponseNotFound()

        return self.get_response(request)
