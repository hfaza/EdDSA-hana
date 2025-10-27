from django.urls import path

from . import views

app_name = "signer"

urlpatterns = [
    path("", views.home, name="home"),
]
