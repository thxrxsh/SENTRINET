from django.shortcuts import render
from django.http import HttpResponse

from . import utils

def overview(request):
    

    response = "SENTRINET"

    return HttpResponse(response)



def scan(request):
    
    
    response = "SCAN"

    return HttpResponse(response)