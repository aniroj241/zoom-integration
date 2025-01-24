from django.urls import path
from .views import ZoomIntegrationAPIView, oauth_callback

urlpatterns = [
    path("integration/", ZoomIntegrationAPIView.as_view(), name="zoom_integration"),
    path("oauth/callback/", oauth_callback, name="oauth_callback"),
]
