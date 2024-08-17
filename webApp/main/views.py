from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.template.response import TemplateResponse
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from datetime import date, timedelta, datetime

from .forms import RegistrationForm, LoginForm
from .utils import startScan, stopScan

SCAN_RUNNING = False



def register(request, template='register.html'):
    if request.user.is_authenticated:
        return redirect('overview')

    form = RegistrationForm()

    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        if form.is_valid():
            form.save()
            return redirect(request.GET.get('next', 'overview'))


    args = {'title':'SENTRINET | Register', 'register_form':form }
    return TemplateResponse(request, template, args)



def login(request, template='login.html'):
    if request.user.is_authenticated:
        return redirect('overview')

    form = LoginForm()

    if request.method == 'POST':
        form = LoginForm(data=request.POST)

        if form.is_valid():
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                auth_login(request, user)
                return redirect(request.GET.get('next', 'overview'))

    args = {'title': 'SENTRINET | Login', 'login_form': form}
    return TemplateResponse(request, template, args)



def logout(request):
    auth_logout(request=request)
    return redirect('login')









# @login_required(login_url='/login/')
def overview(request):
    
    if request.method == 'GET':

        response = "SENTRINET"

        return HttpResponse(response)





# @csrf_exempt
# @login_required(login_url='/login/')
def scan(request):
    global SCAN_RUNNING
    
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'start' and not SCAN_RUNNING:
            startScan() 
            SCAN_RUNNING = True
            response = "Processes started."
        
        elif action == 'stop' and SCAN_RUNNING:
            stopScan(request)
            SCAN_RUNNING = False
            response = "Processes stopped."
        
        else:
            response = "Invalid action or processes already in the requested state."

    else:
        response = "POST 'action' to 'start' to start scan.\nPOST 'action' to 'stop' to stop scan"
    
    return HttpResponse(response)




