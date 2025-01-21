from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.views.generic import View
from .indieauthclient import IndieAuthClient, Request as IndieRequest
import logging
from urllib.parse import urljoin
import requests

logger = logging.getLogger(__name__)

def get_client_metadata_url(request):
    return "https://djangomicropubpoc.onrender.com/client/metadata"
    return request.build_absolute_uri(reverse("client:metadata"))

def get_redirect_url(request):
    return request.build_absolute_uri(reverse("client:oauthcallback"))

session_key = "indieauth_state"

# Create your views here.
class IndexView(View):
    def get(self, request): 
        return render(request, "client/index.html", {
            "auth": request.session.get("auth")
        })
    
    def post(self, request):
        try:
            client = IndieAuthClient(get_client_metadata_url(request))
            logger.debug("Client: %s" % client)

            user_profile_url = request.POST.get('user-profile-url')

            user_metadata = client.get_user_metadata(user_profile_url)
            logger.debug("user_metadata: %s" % user_metadata)

            server_metadata = client.get_indieauth_server_metadata(user_metadata)
            logger.debug("server_metadata: %s" % server_metadata)

            code_verifier = client.create_code_verifier(128)
            logger.debug("code_verifier: %s" % code_verifier)

            code_challenge_method = "S256"
            code_challenge = client.create_code_challenge(code_verifier, code_challenge_method)
            logger.debug("code_challenge: %s" % code_challenge)

            url, headers, body = client.prepare_authorization_request(
                server_metadata.get("authorization_endpoint"), 
                redirect_url=get_redirect_url(request),
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                me=client.user_profile_url,
                scope=["profile","create","update","delete"]
            )
            logger.debug("url: %s" % url)
            logger.debug("headers: %s" % headers)
            logger.debug("body: %s" % body)

            request.session[session_key] = {
                "user_metadata": user_metadata,
                "server_metadata": server_metadata,
                "code_verifier": code_verifier
            }

            return redirect(url, headers=headers, body=body)

            return HttpResponse(body, headers=headers, status=302)
        except Exception as e:
            logger.debug(e)
            return render(request, "client/index.html", {
                "error": e,
                "userprofileurl": user_profile_url
            })

class CallbackView(View):
    def get(self, request): 
        error = request.GET.get("error")

        if error:
            return HttpResponse("%s: %s" % (error, request.GET.get("error_description")))
        

        client = IndieAuthClient(get_client_metadata_url(request))

        saved_data = request.session[session_key]

        url, headers, body = client.prepare_token_request(
            saved_data.get("server_metadata").get("token_endpoint"), 
            request.get_full_path(),
            code_verifier=saved_data.get("code_verifier"),
            redirect_url=get_redirect_url(request))
        logger.debug("url: %s" % url)
        logger.debug("headers: %s" % headers)
        logger.debug("body: %s" % body)

        r = requests.post(url, headers=headers, data=body)
        logger.debug("r: %s" % r)

        request.session['auth'] = r.json()

        return redirect("client:index")


def metadata(request):
    return JsonResponse({
        "client_id": request.build_absolute_uri(reverse("client:metadata")),
        "client_id": request.build_absolute_uri(reverse("client:metadata")),
        "client_uri": request.build_absolute_uri(reverse("client:index")),
        "redirect_uris": [
            request.build_absolute_uri(reverse("client:oauthcallback")),
            urljoin("http://localhost:8000", reverse("client:oauthcallback"))
        ]
    })