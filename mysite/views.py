from django.shortcuts import render
from micropub.views import MicropubBase
from django.views.generic import DetailView
from .models import Note
from django.urls import resolve
from urllib.parse import urlparse
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
def index(request):
    return render(request, "mysite/index.html")

@method_decorator(csrf_exempt, name="dispatch")
class MicropubView(MicropubBase):
    def get_syndication_targets(self):
        return []
    
    def get_item_from_url(self, url):
        parsed = urlparse(url)

        if parsed.hostname not in settings.ALLOWED_HOSTS:
            print("hostname %s not in allowed hosts" % parsed.hostname)

        try:
            match = resolve(parsed.path)
        except Exception as e:
            print(e)
            return None
        
        print(match)

        if match.url_name == "notes-detail":
            print(match.url_name)
            print(match.kwargs.get("pk"))
            return Note.objects.get(pk=match.kwargs.get("pk"))
        
        return None
    
class NotesDetail(DetailView):
    model = Note
