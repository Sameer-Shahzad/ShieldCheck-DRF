from django.urls import path
from . import views

urlpatterns = [
   path('v1/scan/', views.scanView.as_view(), name='scan'),
]