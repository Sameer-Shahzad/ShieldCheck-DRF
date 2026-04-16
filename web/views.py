from django.shortcuts import render

# Create your views here.


def home (request):
    return render(request, 'index.html')

def history (request):
    id = request.GET.get('id')
    url = request.GET.get('url')
    scan_date = request.GET.get('scan_date')
    findings = request.GET.get('findings')
    
    
    return render(request, 'history.html')

def about (request):
    return render(request, 'footerLinks/about.html')

def privacy (request):
    return render(request, 'footerLinks/privacy.html')

def services (request):
    return render(request, 'footerLinks/services.html')


def report (request):
    return render(request, 'report.html')