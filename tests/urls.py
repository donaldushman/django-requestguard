from django.http import HttpResponse
from django.urls import path


def ok_view(request, *args, **kwargs):
    return HttpResponse("ok")


urlpatterns = [
    path("", ok_view),
    path("<path:any_path>", ok_view),
]
