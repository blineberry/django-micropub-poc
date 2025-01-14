from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.urls import reverse

# Create your views here.
def index(request):
    return render(request, "myapp/index.html")

def client_id(request):
    return JsonResponse({
        "client_id": request.build_absolute_uri(reverse("myapp:clientid"))
    })