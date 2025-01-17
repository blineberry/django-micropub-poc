from django.urls import path

from . import views

app_name = 'indieauth'
urlpatterns = [
    path("authorization", views.AuthView.as_view(), name="authorization"),
    path("token", views.TokenView.as_view(), name="token"),
    path("introspect", views.introspect, name="introspect"),
    path('.well-known/oauth-authorization-server', views.metadata, name="metadata"),
    path("", views.index, name="issuer")
]