from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.views.generic import View
from .indieauthclient import Client, Request as IndieRequest
import logging
from .indieauthclient import InvalidProfileUrlException

logger = logging.getLogger(__name__)
client = Client()

# Create your views here.
class IndexView(View):
    def __init__(self, **kwargs):
        self._client = client

    def get(self, request): 
        return render(request, "client/index.html")
    
    def post(self, request):
        logger.info(request)

        indie_request = IndieRequest(
            profile_url=request.POST.get('user-profile-url')
            )
                     
        try:
            headers, body, status = self._client.create_login_response(indie_request)
        except Exception as e:
            logger.debug(e)
            return render(request, "client/index.html", {
                "error": e,
                "userprofileurl": indie_request.profile_url
            })
        
        return HttpResponse(body, headers=headers, status=status)

def metadata(request):
    return JsonResponse({
        "client_id": request.build_absolute_uri(reverse("myapp:clientid")),
        "client_uri": request.build_absolute_uri(reverse("myapp:index"))
    })