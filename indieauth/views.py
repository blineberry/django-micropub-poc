from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.urls import reverse
from django.views.generic import View
from indieauth.authrequest import AuthRequest
from indieauth.validator import Validator

from oauthlib.oauth2 import WebApplicationServer, FatalClientError, OAuth2Error

validator = Validator()
server = WebApplicationServer(validator)

# Create your views here.
def index(request):
    return HttpResponse(status=404)

class AuthView(View):
    def __init__(self, **kwargs):
        self._authorization_endpoint = server
        super().__init__(**kwargs)

    def extract_params(self, request): 
        return (request.build_absolute_uri() ,request.method, request.body, request.headers)
    
    def response_from_error(self, error):
        return HttpResponseBadRequest(error)

    def get(self, request, *args, **kwargs):
        uri, http_method, body, headers = self.extract_params(request)

        try:
            scopes, credentials = self._authorization_endpoint.validate_authorization_request(uri,http_method,body,headers)
            return HttpResponse()
        
        # Errors that should be shown to the user on the provider website
        except FatalClientError as e:
            return self.response_from_error(e)
        
        # Errors embedded in the redirect URI back to the client
        except OAuth2Error as e:
            return HttpResponseRedirect(e.in_uri(e.redirect_uri))

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