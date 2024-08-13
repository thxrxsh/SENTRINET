from django.urls import path
from . import views

urlpatterns = [
    path('', views.overview, name='overview'),
    path('scan/', views.scan, name='scan'),
    
]