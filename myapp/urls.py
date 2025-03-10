from django.urls import path, include

from . import views

app_name = 'myapp'
urlpatterns = [
    path("", views.index, name="index"),
    path("accounts/", include("django.contrib.auth.urls"))
]