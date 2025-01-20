from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.views.generic import View
from .indieauthclient import IndieAuthClient, Request as IndieRequest
import logging

logger = logging.getLogger(__name__)

def get_client_metadata_url(request):
    return request.build_absolute_uri(reverse("client:metadata"))

def get_redirect_url(request):
    return request.build_absolute_uri(reverse("client:oauthcallback"))

# Create your views here.
class IndexView(View):
    def get(self, request): 
        return render(request, "client/index.html")
    
    def post(self, request):
        try:
            client = IndieAuthClient(
                get_client_metadata_url(request),
                request.POST.get('user-profile-url'))
            logger.debug("Client: %s" % client)

            user_metadata = client.get_user_metadata(client.user_profile_url)
            logger.debug("user_metadata: %s" % user_metadata)

            server_metadata = client.get_indieauth_server_metadata(user_metadata)
            logger.debug("server_metadata: %s" % server_metadata)

            url, headers, body = client.prepare_authorization_request(server_metadata.get("authorization_endpoint"), redirect_url=get_redirect_url(request))
            logger.debug("url: %s" % url)
            logger.debug("headers: %s" % headers)
            logger.debug("body: %s" % body)

            return redirect(url, headers=headers, body=body)

            return HttpResponse(body, headers=headers, status=302)
        except Exception as e:
            logger.debug(e)
            return render(request, "client/index.html", {
                "error": e,
                "userprofileurl": request.POST.get('user-profile-url')
            })
        

def metadata(request):
    return JsonResponse({
        "client_id": request.build_absolute_uri(reverse("client:metadata")),
        "client_uri": request.build_absolute_uri(reverse("client:index"))
    })
def callback(request):
    return HttpResponse(None, status=501)