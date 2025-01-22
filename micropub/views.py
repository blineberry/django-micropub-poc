from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.generic import View
from .micropub import Client
from .models import MicroformatModel
import json

# Create your views here.
class MicropubBase(View):
    def render_config_response(self, request):
        return JsonResponse({
            "syndicate_to": self.get_syndication_targets()
        })
    
    def get_syndication_targets(self):
        """
        Return the syndication targets supported. See https://micropub.spec.indieweb.org/#syndication-targets
        If none, return [].
        """
        raise NotImplementedError("This method must be implemented in inherited view.")

    def get_item_from_url(self, url):
        """
        Queries for the item as indicated by the provided url. If the item
        does not exist or cannot be queried, return None.
        """
        raise NotImplementedError("This method must be implemented in inherited view.")

    def get_source_content(self, item, properties):
        """
        Returns the item in microformat json representation as specced.

        If the item implements MicroformatModel, then we can use to_mf_json,
        otherwise the inherited view should implement.
        """

        if isinstance(item, MicroformatModel):
            return item.to_mf_mson(properties)
        
        raise NotImplementedError("Views should implement this method if handling models that don't implement MicroformatModel.")

    def render_source_response(self, request):
        url = request.GET.get("url", None)

        if url is None:
            return HttpResponse("url is required for a source request.", status=400)
        
        item = self.get_item_from_url(url)
        print(item)

        if item is None:
            return HttpResponse("url does not identify valid content.", status=400)

        print(request.GET)

        properties = request.GET.get("properties",None)
        print(properties)
        if (properties is None or len(properties) <= 1) and "properties" in request.GET:
            properties = request.GET.getlist("properties[]", None)

        print(properties)

        response_content = self.get_source_content(item, properties)

        return JsonResponse(response_content)

    def render_syndicate_to_response(self, request):
        return JsonResponse({
            "syndicate-to": self.get_syndication_targets()
        })

    def get(self, request, *args, **kwargs):
        q = request.GET.get("q", "")

        if q == "config":
            return self.render_config_response(request)

        if q == "source":
            return self.render_source_response(request)

        if q == "syndicate-to":
            return self.render_syndicate_to_response(request)

        return HttpResponse("'q' parameter is required", status=400)

    def post(self, request, *args, **kwargs):
        request_body = None
        request_files = None

        if request.content_type == "application/json":
            request_body = json.loads(request.body)
        elif request.content_type == "x-www-form-urlencoded":
            request_body = self.form_data_to_mf_json(request.body)
        elif request.content_type == "multipart/form-data":
            request_body = self.form_data_to_mf_json(request.body)
            request_files = request.FILES
        else:
            return HttpResponse("unsupported content_type %s" % request.content_type, status=400)
        
        if "action" in request_body:
            if request_body["action"] == "delete":
                