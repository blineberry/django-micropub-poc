from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.contrib.auth.views import LoginView

# Create your views here.
def index(request):
    return render(request, "myapp/index.html")

def client_id(request):
    return JsonResponse({
        "client_id": request.build_absolute_uri(reverse("myapp:clientid")),
        "client_uri": request.build_absolute_uri(reverse("myapp:index"))
    })

class MyLoginView(LoginView):
    pass