from django.urls import path
from . import views

urlpatterns = [
    path('', views.overview, name='overview'),
    path('scan/', views.scan, name='scan'),
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),
]