from django.urls import path, include

from . import views

app_name = 'mysite'
urlpatterns = [
    path("", views.index, name="index"),
    path("micropub", views.MicropubView.as_view(), name="micropub"),
    path("notes/<int:pk>", views.NotesDetail.as_view(), name="notes-detail")
]