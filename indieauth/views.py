from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.views.generic import View
from indieauth.authrequest import AuthRequest


# Create your views here.
def index(request):
    return HttpResponse(status=404)

class AuthView(View):
    def get(self, request, *args, **kwargs):
        auth_request = AuthRequest(request.GET)
        auth_request.validate()

        if auth_request.is_valid is False:
            return HttpResponse(status=400, content=auth_request.validation_error)

        return JsonResponse(vars(auth_request))
    def post(self, request, *args, **kwargs):
        return HttpResponse(status=501)

def token(request):
    return HttpResponse(status=501)

def introspect(request):
    return HttpResponse(status=501)

def metadata(request):
    return JsonResponse({
        "issuer": request.build_absolute_uri(reverse("indieauth:issuer")),
        "authorization_endpoint": request.build_absolute_uri(reverse("indieauth:authorization")),
        "token_endpoint": request.build_absolute_uri(reverse("indieauth:token")),
        "scopes_supported": [],
        "introspection_endpoint": request.build_absolute_uri(reverse("indieauth:introspect")),
        "code_challenge_methods_supported": ["S256"]
    })