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

            if parsed.scheme not in ['https']:
                return Response({"error": "Only HTTPS allowed"}, status=400)

            hostname = parsed.hostname
            hostname = hostname.lower().strip()

            if not hostname:
                return Response({"error": "Invalid URL"}, status=400)

            port = parsed.port
            if port and port not in [443]:
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

            elif 'unsafe-inline' in csp.lower() or 'unsafe-eval' in csp.lower():
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

                if 'max-age' in hsts.lower():
                    import re
                    match = re.search(r'max-age=(\d+)', hsts)
                    max_age_number = int(match.group(1)) if match else 0

                    if max_age_number < 31536000:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Short HSTS duration increases risk of SSL stripping'
                        hsts_solution = 'Set max-age to at least 31536000 seconds.'

                    elif 'includesubdomains' not in hsts.lower():
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
                    
                
            x_frame = headers.get('X-Frame-Options', '')
            
            if not x_frame:
                x_frame_status = 'MISSING'
                x_frame_impact = 'High'
                x_frame_solution = 'Implement X-Frame-Options to prevent clickjacking attacks.'
            elif 'deny' in x_frame.lower() or 'sameorigin' in x_frame.lower():
                
                x_frame_status = 'SECURE'
                x_frame_impact = 'Low'
                x_frame_solution = 'X-Frame-Options is properly configured.'
            else:
                x_frame_status = 'WARNING'
                x_frame_impact = 'Medium'
                x_frame_solution = 'Use DENY or SAMEORIGIN for X-Frame-Options.'
                
                
            x_content_type = headers.get('X-Content-Type-Options', '')
            
            if not x_content_type:
                x_content_type_status = 'MISSING'
                x_content_type_impact = 'Medium'
                x_content_type_solution = 'Implement X-Content-Type-Options to prevent MIME type sniffing.'
            elif 'nosniff' in x_content_type.lower():
                x_content_type_status = 'SECURE'
                x_content_type_impact = 'Low'
                x_content_type_solution = 'X-Content-Type-Options is properly configured.'
            else:
                x_content_type_status = 'WARNING'
                x_content_type_impact = 'Medium'
                x_content_type_solution = 'Use nosniff for X-Content-Type-Options.'
                
                
            referer_policy = headers.get('Referrer-Policy', '')
            
            if not referer_policy:
                referer_policy_status = 'MISSING'
                referer_policy_impact = 'Medium'
                referer_policy_solution = 'Implement Referrer-Policy to control referrer information sent with requests.'
            elif 'no-referrer' in referer_policy.lower() or 'same-origin' in referer_policy.lower() or 'strict-origin-when-cross-origin' in referer_policy.lower():
                referer_policy_status = 'SECURE'
                referer_policy_impact = 'Low'
                referer_policy_solution = 'Referrer-Policy is properly configured.'
            else:
                referer_policy_status = 'WARNING'
                referer_policy_impact = 'Low'
                referer_policy_solution = 'Use no-referrer or same-origin for Referrer-Policy.'
                
            permission_policy = headers.get('Permissions-Policy', '')
            if not permission_policy:
                permission_policy_status = 'MISSING'
                permission_policy_impact = 'Low'
                permission_policy_solution = 'Implement Permissions-Policy to control access to powerful features.'
            elif 'geolocation' in permission_policy.lower() or 'camera' in permission_policy.lower or 'microphone' in permission_policy.lower():
                permission_policy_status = 'WARNING'
                permission_policy_impact = 'Medium'
                permission_policy_solution = 'Review Permissions-Policy to restrict access to sensitive features.'
                
                
        
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
            },
            "x_frame": {
                "status": x_frame_status,
                "impact": x_frame_impact,
                "solution": x_frame_solution
            },
            "x_content_type": {
                "status": x_content_type_status,
                "impact": x_content_type_impact,
                "solution": x_content_type_solution
            },
            "referer-policy": {
                "status": referer_policy_status,
                "impact": referer_policy_impact,
                "solution": referer_policy_solution
            }
            
        }, status=200)
                
                    
        else:
            return Response({"error": "Invalid serializer data"}, status=400)

       