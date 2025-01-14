from django.shortcuts import render
from django.http import HttpResponse, JsonResponse

# Create your views here.
def index(request):
    return render(request, "myapp/index.html")

def client_id(request):
    return JsonResponse({})