from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.urls import reverse
from django.views.generic import View
from indieauth.authrequest import AuthRequest
from indieauth.validator import Validator
from django.contrib.auth.mixins import LoginRequiredMixin

from oauthlib.oauth2 import WebApplicationServer, FatalClientError, OAuth2Error, InvalidGrantError
from oauthlib.common import add_params_to_uri, Request as OAuthRequest
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json

import logging
import oauthlib
import sys
oauthlib.set_debug(True)
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

validator = Validator()
server = WebApplicationServer(validator)

def extract_params(request): 
        return (request.build_absolute_uri() ,request.method, request.body, request.headers)

# Create your views here.
def index(request):
    return HttpResponse(status=404)

class AuthView(LoginRequiredMixin, View):

    session_key = 'oauth2_credentials'

    def __init__(self, **kwargs):
        self._authorization_endpoint = server
        super().__init__(**kwargs)    
    
    def response_from_error(self, error):
        return HttpResponseBadRequest(error)

    def get(self, request, *args, **kwargs):        
        uri, http_method, body, headers = extract_params(request)

        try:
            scopes, credentials = self._authorization_endpoint.validate_authorization_request(uri,http_method,body,headers)
            print(credentials)
            
            credentials.update({ "client": credentials.get('request').client })
            credentials.update({'request': None})

            request.session[self.session_key] = credentials
            
            return render(request, "indieauth/auth.html", { 
                "scopes": scopes,
                "credentials": credentials
            })
        
        # Errors that should be shown to the user on the provider website
        except FatalClientError as e:
            return self.response_from_error(e)
        
        # Errors embedded in the redirect URI back to the client
        except OAuth2Error as e:
            return HttpResponseRedirect(e.in_uri(e.redirect_uri))
        
    def post(self, request, *args, **kwargs):
        uri, http_method, body, headers = extract_params(request)

        scopes = request.POST.getlist('scopes')

        credentials = {"user": request.user}
        credentials.update(request.session.get(self.session_key, {}))
        print(credentials)
        try:
            headers, body, status = self._authorization_endpoint.create_authorization_response(
            uri, http_method, body, headers, scopes, credentials)


            # indieauth response needs to include the issuer. adding it to the code
            # here adds it to the query string in the response
            # https://indieauth.spec.indieweb.org/#authorization-response
            location = headers.get('Location')
            headers.update({'Location': add_params_to_uri(location,[("iss",request.build_absolute_uri(reverse("indieauth:issuer")))])})
            
            print(headers)
            print(body)
            print(status)

            return HttpResponse(body,headers=headers,status=status)
            return response_from_return(headers, body, status)

        except FatalClientError as e:
            return self.response_from_error(e)  

@method_decorator(csrf_exempt, name="dispatch")
class TokenView(View):    
    def __init__(self, **kwargs):
        self._token_endpoint = server

    def post(self, request, *args, **kwargs):
        uri, http_method, body, headers = extract_params(request)

        headers, body, status = self._token_endpoint.create_token_response(
                uri, http_method, body, headers, {})

        return HttpResponse(body, headers=headers, status=status)
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