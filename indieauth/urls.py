from django.urls import path

from . import views

app_name = 'indieauth'
urlpatterns = [
    path("authorization", views.AuthView.as_view(), name="authorization"),
    path("token", views.TokenView.as_view(), name="token"),
    path("introspect", views.IntrospectView.as_view(), name="introspect"),
    path("revocation", views.RevocationView.as_view(), name="revocation"),
    path('.well-known/oauth-authorization-server', views.metadata, name="metadata"),
    path("", views.index, name="issuer")
]