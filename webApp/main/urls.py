from django.urls import path
from . import views

urlpatterns = [
    path('set_timezone/', views.set_timezone, name='set_timezone'),
    
    path('', views.home, name='home'),
    path('scan/', views.scan, name='scan'),
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),
    path('account/', views.account, name='account'),
    path('reports/', views.reports, name='reports'),
    path('report/<int:id>/', views.report, name='report'),
    path('alerts/<str:action>/', views.alerts, name='alerts'),
]