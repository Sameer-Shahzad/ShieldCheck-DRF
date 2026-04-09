from os import error

from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.views import APIView, Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from api.serializers import ScanSerializer
import requests
from urllib.parse import urlparse
import socket, ipaddress
# Create your views here.


class scanView(APIView):
    throttle_classes = [UserRateThrottle, AnonRateThrottle]
    
    def post (self, request):
        url = request.data.get('url')
        if not url:
            return Response({"error": "URL is required"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = ScanSerializer(data={'url': url})
        if serializer.is_valid():
            scan_instance = serializer.save()
            target_url = scan_instance.url
            
##### SSRF PROTECTION CODE 
            
            parsed = urlparse(target_url)
            hostname = parsed.hostname

            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                return Response({"error": "Invalid host"}, status=400)

            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return Response({"error": "Access to internal IPs is blocked"}, status=403)

##### HTTP SECURITY HEADERS CHECKING CODE
            
            try:
                response = requests.get(target_url, timeout=10)
            except requests.exceptions.RequestException as e:
                return Response({"error": "something"}, status=400)
        
            try:
                headers = response.headers
                csp = headers.get('Content-Security-Policy', '')
            except Exception as e:
                return Response({"error": "something"}, status=400)

            if not csp:
                csp_status = 'MISSING'
                csp_impact = 'High'
                csp_solution = 'Implement a Content Security Policy to mitigate XSS and data injection attacks.'
            elif 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                csp_status = 'WARNING'
                csp_impact = 'Medium'
                csp_solution = 'Remove unsafe directives from your CSP to enhance security.'
            else:
                csp_status = 'SECURE'
                
            
            try:
                hsts = headers.get ('Strict-Transport-Security', '')
            except error as e:
                return Response({"error": "something"}, status=400)
                
            if not hsts:
                hsts_status = 'MISSING'
                hsts_impact = 'High'
                hsts_solution = 'Implement HSTS to enforce secure connections and protect against protocol downgrade attacks.'
            else:
                
                if 'max-age' in hsts:
                    import re
                    max_age_number = int(re.search(r'max-age=(\d+)', hsts).group(1)) if re.search(r'max-age=(\d+)', hsts) else 0
                    
                    if 'max-age' in hsts and max_age_number < 31536000:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Short HSTS duration increases the risk of SSL stripping and protocol downgrade attacks.'
                        hsts_solution = 'Set max-age to at least 31536000 seconds (1 year) for better security.'    
                        
                    elif 'includeSubDomains' not in hsts and max_age_number >= 31536000:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Unprotected subdomains remain vulnerable to traffic interception and session hijacking.'
                        hsts_solution = 'Include the includeSubDomains directive to ensure all subdomains are protected.'
                        
                    elif 'includeSubDomains' in hsts and 'max-age' in hsts and max_age_number >= 31536000:
                        hsts_status = 'Secure'
                        
                    else:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Low'
                        hsts_solution = 'Verify HSTS directive formatting.'
                        
                else:
                    hsts_status = 'WARNING'
                    hsts_impact = 'Max age is not present in HSTS header.'
                    hsts_solution = 'Set max-age to at least 31536000 seconds (1 year) for better security.'
            
        else:
            return Response({"error": "something"}, status=400)
        
    

        
        