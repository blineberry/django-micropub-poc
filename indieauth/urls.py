from django.urls import path

from . import views

app_name = 'indieauth'
urlpatterns = [
    path("authorization", views.auth, name="authorization"),
]