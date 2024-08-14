from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from .utils import startProcesses, stopProcesses

processes_running = False


def overview(request):
    
    if request.method == 'GET':

        response = "SENTRINET"

        return HttpResponse(response)





@csrf_exempt
def scan(request):
    global processes_running
    
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'start' and not processes_running:
            startProcesses() 
            processes_running = True
            response = "Processes started."
        
        elif action == 'stop' and processes_running:
            stopProcesses()
            processes_running = False
            response = "Processes stopped."
        
        else:
            response = "Invalid action or processes already in the requested state."

    else:
        response = "POST 'action' to 'start' to start scan.\nPOST 'action' to 'stop' to stop scan"
    
    return HttpResponse(response)
