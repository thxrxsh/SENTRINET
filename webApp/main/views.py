from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
from django.template.response import TemplateResponse
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

import pytz
from datetime import date, timedelta, datetime
import json

from .forms import RegistrationForm, LoginForm
from .utils import *

SCAN_RUNNING = False







def set_timezone(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_timezone = data.get('timezone')

            if user_timezone in pytz.all_timezones:
                request.session['django_timezone'] = user_timezone
                timezone.activate(pytz.timezone(user_timezone))

            return JsonResponse({'status': 'success'})

        except (ValueError, KeyError):
            return JsonResponse({'status': 'error', 'message': 'Invalid timezone'}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)





def register(request, template='register.html'):
    if request.user.is_authenticated:
        return redirect('home')

    form = RegistrationForm()

    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        if form.is_valid():
            form.save()
            request.session['new_alerts_count'] = 0
            return redirect(request.GET.get('next', 'home'))


    args = {'title':'SENTRINET | Register', 'register_form':form }
    return TemplateResponse(request, template, args)



def login(request, template='login.html'):
    if request.user.is_authenticated:
        return redirect('home')

    form = LoginForm()

    if request.method == 'POST':
        form = LoginForm(data=request.POST)

        if form.is_valid():
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                auth_login(request, user)
                request.session['new_alerts_count'] = 0
                return redirect(request.GET.get('next', 'home'))

    args = {'title': 'SENTRINET | Login', 'login_form': form}
    return TemplateResponse(request, template, args)





def logout(request):
    auth_logout(request=request)
    return redirect('login')





@login_required(login_url='/login/')
def account(request, template='dashboard.html'):
    


    args = {'title':'SENTRINET | Account' }

    return TemplateResponse(request, template, args)



@login_required(login_url='/login/')
def home(request, template='dashboard.html'):
    global SCAN_RUNNING
    
    last_report = getLastReportDetails(request)
    print(last_report)
    args = {
        'title':'SENTRINET | Home',
        'SCAN_RUNNING': 1 if SCAN_RUNNING else 0,
        'last_report' : last_report,
    }

    return TemplateResponse(request, template, args)





@login_required(login_url='/login/')
def scan(request, template='dashboard.html'):
    global SCAN_RUNNING, RECORD_ID

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'start' and not SCAN_RUNNING:
            startScan() 
            SCAN_RUNNING = True
            return JsonResponse({'status': 'scan-started'})
        
        elif action == 'stop' and SCAN_RUNNING:
            stopScan(request)
            SCAN_RUNNING = False
            scan_summary = getScanSummary(request)
            return JsonResponse({'status': 'scan-stopped', 'scan_summary': scan_summary})
        
        elif action == 'status'  and SCAN_RUNNING:
            live_status = liveStatus(request)
            return JsonResponse({'live_status': live_status})


        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid action or processes already in the requested state.'})

    # Handle GET requests or other methods
    args = {
        'title': 'SENTRINET | Scan',
        'SCAN_RUNNING': 1 if SCAN_RUNNING else 0,
    }

    return render(request, template, args)





@login_required(login_url='/login/')
def reports(request, template='dashboard.html'):
    global SCAN_RUNNING

    if request.method == 'GET':
        reports_list = getReportsList(request)

        if SCAN_RUNNING:
            args = {
                'title': 'SENTRINET | Reports',
                'reports': reports_list,
                'live_report': 1,
            }
        else:
            args = {
                'title': 'SENTRINET | Reports',
                'reports': reports_list,
                'live_report': None,
            }

        return TemplateResponse(request, template, args)

    elif request.method == 'POST':
        report_id = request.POST.get('delete_report')
        
        if report_id and deleteReport(request, report_id):
            return JsonResponse({'status': 'delete-ok'})
        else:
            return JsonResponse({'status': 'delete-failed'}, status=400)







@login_required(login_url='/login/')
def report(request, id, template='dashboard.html'):

    if (id != 0):

        report_details = getReport(request, id)
        args = {
            'title' : 'SENTRINET | Report',
            'report' : json.dumps(report_details, sort_keys=True, indent=1, cls=DjangoJSONEncoder)
            }

    elif (id == 0 and SCAN_RUNNING):

        if request.method == 'GET':

            live_report = liveReport(request)
            args = {
                'title' : 'SENTRINET | Report',
                'report' : json.dumps(live_report, sort_keys=True, indent=1, cls=DjangoJSONEncoder)
                }

        elif request.method == 'POST':
            
            live_report = liveReport(request)
            return JsonResponse({'live_report': live_report})

    else:
        return redirect('reports')


    return TemplateResponse(request, template, args)





@login_required(login_url='/login/')
def alerts(request, action):

    if request.method == 'POST':

        if action == 'get':
            return JsonResponse({'alerts' : getAlerts(request) })

        elif action == 'check':
            return JsonResponse({'new_alerts_count' : checkForNewAlerts(request), 'total_alerts_count' : checkForTotalAlerts(request) })

        elif action == 'add':
            message = request.POST.get('message')
            status = request.POST.get('status')
            return JsonResponse({'alert' : addAlert(request, message, status) })

        elif action == 'delete':
            alert_id = request.POST.get('alert_id')
            return JsonResponse({'response' : removeAlert(alert_id) })

