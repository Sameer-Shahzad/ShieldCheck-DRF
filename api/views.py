from os import error

from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.views import APIView, Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from api.serializers import ScanSerializer
import requests
from urllib.parse import urlparse
import socket, ipaddress


class scanView(APIView):
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def post(self, request):
        url = request.data.get('url')

        if not url:
            return Response({"error": "URL is required"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ScanSerializer(data={'url': url})

        if serializer.is_valid():
            scan_instance = serializer.save()
            target_url = scan_instance.url

##### SSRF PROTECTION CODE #####

            parsed = urlparse(target_url)

            if parsed.scheme not in ['http', 'https']:
                return Response({"error": "Only HTTP/HTTPS allowed"}, status=400)

            hostname = parsed.hostname
            hostname = hostname.lower().strip()

            if not hostname:
                return Response({"error": "Invalid URL"}, status=400)

            port = parsed.port
            if port and port not in [80, 443]:
                return Response({"error": "Blocked unsafe port"}, status=403)

            try:
                # 2. Resolve all IPs (IPv4 + IPv6)
                addr_info = socket.getaddrinfo(hostname, None)

                for result in addr_info:
                    ip = result[4][0]
                    ip_obj = ipaddress.ip_address(ip)

                    if (
                        ip_obj.is_private or
                        ip_obj.is_loopback or
                        ip_obj.is_reserved or
                        ip_obj.is_link_local or
                        ip_obj.is_multicast
                    ):
                        return Response(
                            {"error": "Access to internal or unsafe IPs is blocked"},
                            status=403
                        )

            except socket.gaierror:
                return Response({"error": "DNS resolution failed"}, status=400)


##### HTTP SECURITY HEADERS CHECKING CODE #####

            try:
                redirect_response = requests.get(target_url, timeout=10, allow_redirects=False)
            except requests.exceptions.RequestException:
                return Response({"error": "something"}, status=400)

            headers = redirect_response.headers

            csp = headers.get('Content-Security-Policy', '')

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
                csp_impact = 'Low'
                csp_solution = 'CSP is properly configured.'

            hsts = headers.get('Strict-Transport-Security', '')

            if not hsts:
                hsts_status = 'MISSING'
                hsts_impact = 'High'
                hsts_solution = 'Implement HSTS to enforce secure connections and protect against protocol downgrade attacks.'

            else:

                if 'max-age' in hsts:
                    import re
                    match = re.search(r'max-age=(\d+)', hsts)
                    max_age_number = int(match.group(1)) if match else 0

                    if max_age_number < 31536000:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Short HSTS duration increases risk of SSL stripping'
                        hsts_solution = 'Set max-age to at least 31536000 seconds.'

                    elif 'includeSubDomains' not in hsts:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Subdomains not protected'
                        hsts_solution = 'Include includeSubDomains directive.'

                    else:
                        hsts_status = 'SECURE'
                        hsts_impact = 'Good configuration'
                        hsts_solution = 'HSTS is properly configured.'

                else:
                    hsts_status = 'WARNING'
                    hsts_impact = 'Max age missing'
                    hsts_solution = 'Set max-age to at least 31536000 seconds.'

        else:
            return Response({"error": "Invalid serializer data"}, status=400)

        return Response({
            "csp": {
                "status": csp_status,
                "impact": csp_impact,
                "solution": csp_solution
            },
            "hsts": {
                "status": hsts_status,
                "impact": hsts_impact,
                "solution": hsts_solution
            }
        }, status=200)