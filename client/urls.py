from django.urls import path, include

from . import views

app_name = 'client'
urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path("metadata", views.metadata, name="metadata"),
    path("callback", views.CallbackView.as_view(), name="oauthcallback"),
]