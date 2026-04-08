from django.shortcuts import render

# Create your views here.


def home (request):
    return render(request, 'index.html')

def history (request):
    return render(request, 'history.html')

def about (request):
    return render(request, 'footerLinks/about.html')

def privacy (request):
    return render(request, 'footerLinks/privacy.html')

def services (request):
    return render(request, 'footerLinks/services.html')


def scanDetails (request):
    return render(request, 'scan_result.html')