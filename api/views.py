from os import error

from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.views import APIView, Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from api.serializers import ScanSerializer
import requests
from urllib.parse import urlparse
import socket, ipaddress, re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests.exceptions
import re

class scanView(APIView):
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def post(self, request):
        url = request.data.get('url')
        if not request.session.session_key:
            request.session.create()
        request.session['initiated'] = True
        request.session.modified = True
        
        session_id = request.session.session_key

        if not url:
            return Response({"error": "URL is required"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ScanSerializer(data={'url': url, 'session_id': session_id})

        if serializer.is_valid():
            scan_instance = serializer.save()
            target_url = scan_instance.url

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
            resolved_ip = None
            try:
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
                    resolved_ip = ip

            except socket.gaierror:
                return Response({"error": "DNS resolution failed"}, status=400)

            headers_for_scan = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }

            try:
                redirect_response = requests.get(
                    target_url, 
                    headers=headers_for_scan, 
                    timeout=10, 
                    allow_redirects=True, 
                    verify=False
                )
                headers = redirect_response.headers
            except Exception as e:
                return Response({"error": f"Scan failed: {str(e)}"}, status=400)
                
            headers = redirect_response.headers

            csp = headers.get('Content-Security-Policy', '')

            if not csp:
                csp_status = 'MISSING'
                csp_impact = 'High'
                csp_solution = 'Implement a Content Security Policy to mitigate XSS and data injection attacks.'

            elif 'unsafe-inline' in csp.lower() or 'unsafe-eval' in csp.lower():
                csp_status = 'WARNING'
                csp_impact = 'High'
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
                    match = re.search(r'max-age=(\d+)', hsts)
                    max_age_number = int(match.group(1)) if match else 0

                    if max_age_number < 31536000:
                        hsts_status = 'WARNING'
                        hsts_impact = 'Medium'
                        hsts_solution = 'Set max-age to at least 31536000 seconds.'

                    elif 'includesubdomains' not in hsts.lower():
                        hsts_status = 'WARNING'
                        hsts_impact = 'Medium'
                        hsts_solution = 'Include includeSubDomains directive.'

                    else:
                        hsts_status = 'SECURE'
                        hsts_impact = 'Low'
                        hsts_solution = 'HSTS is properly configured.'

                else:
                    hsts_status = 'WARNING'
                    hsts_impact = 'Medium'
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
                permission_policy_solution = 'Implement Permissions-Policy to control access.'
            elif any(x in permission_policy.lower() for x in ['geolocation', 'camera', 'microphone']):
                permission_policy_status = 'WARNING'
                permission_policy_impact = 'Medium'
                permission_policy_solution = 'Review sensitive feature access.'
            else:
                permission_policy_status = 'SECURE'
                permission_policy_impact = 'Low'
                permission_policy_solution = 'Permissions-Policy is present.'
            
            set_cookie = headers.get('Set-Cookie', '')
        
            if 'httponly' in set_cookie.lower():
                set_cookie_httpOnly_status = 'SECURE'
                set_cookie_httpOnly_impact = 'Low'
                set_cookie_httpOnly_solution = 'HttpOnly flag is set for cookies, which is good.'
                if 'secure' in set_cookie.lower():
                    set_cookie_secure_status = 'SECURE'
                    set_cookie_secure_impact = 'Low'
                    set_cookie_secure_solution = 'Secure flag is set for cookies, which is good.'
                    if 'samesite=strict' in set_cookie.lower() or 'samesite=lax' in set_cookie.lower():
                        set_cookie_status = 'SECURE'
                        set_cookie_impact = 'Medium'
                        set_cookie_solution = 'Cookies are properly configured. HttpOnly, Secure, and SameSite flags are set.'
                    elif 'samesite=none' in set_cookie.lower():
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'High'
                        set_cookie_solution = 'Strictly avoid using SameSite=None unless necessary, as it allows cross-site cookie usage. However, HttpOnly and Secure flags are set, which is good.'
                    else:
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'High'
                        set_cookie_solution = 'None of the required flags are set for cookies. Consider setting SameSite attribute to Strict or Lax for cookies to enhance security.'
                else:
                    set_cookie_secure_status = 'WARNING'
                    set_cookie_secure_impact = 'High'
                    set_cookie_secure_solution = 'Use Secure flag for cookies to ensure they are only sent over HTTPS.'
                    if 'samesite=strict' in set_cookie.lower() or 'samesite=lax' in set_cookie.lower():
                        set_cookie_status = 'SECURE'
                        set_cookie_impact = 'Medium'
                        set_cookie_solution = 'Cookies are properly configured. HttpOnly, Secure, and SameSite flags are set.'
                    elif 'samesite=none' in set_cookie.lower():
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'High'
                        set_cookie_solution = 'Strictly avoid using SameSite=None unless necessary, as it allows cross-site cookie usage. However, HttpOnly and Secure flags are set, which is good.'
                    else:
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'High'
                        set_cookie_solution = 'None of the required flags are set for cookies. Consider setting SameSite attribute to Strict or Lax for cookies to enhance security.'
            else:
                set_cookie_httpOnly_status = 'WARNING'
                set_cookie_httpOnly_impact = 'Medium'
                set_cookie_httpOnly_solution = 'Use HttpOnly flag for cookies to mitigate XSS risks.'
                if 'secure' in set_cookie.lower():
                    set_cookie_secure_status = 'SECURE'
                    set_cookie_secure_impact = 'Low'
                    set_cookie_secure_solution = 'Secure flag is set for cookies, which is good.'
                    if 'samesite=strict' in set_cookie.lower() or 'samesite=lax' in set_cookie.lower():
                        set_cookie_status = 'SECURE'
                        set_cookie_impact = 'Medium'
                        set_cookie_solution = 'Cookies are properly configured. HttpOnly, Secure, and SameSite flags are set.'
                    elif 'samesite=none' in set_cookie.lower():
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'Critical'
                        set_cookie_solution = 'Strictly avoid using SameSite=None unless necessary, as it allows cross-site cookie usage. However, HttpOnly and Secure flags are set, which is good.'
                    else:
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'High'
                        set_cookie_solution = 'None of the required flags are set for cookies. Consider setting SameSite attribute to Strict or Lax for cookies to enhance security.'
                else:
                    set_cookie_secure_status = 'WARNING'
                    set_cookie_secure_impact = 'High'
                    set_cookie_secure_solution = 'Use Secure flag for cookies to ensure they are only sent over HTTPS.'
                    if 'samesite=strict' in set_cookie.lower() or 'samesite=lax' in set_cookie.lower():
                        set_cookie_status = 'SECURE'
                        set_cookie_impact = 'Medium'
                        set_cookie_solution = 'Cookies are properly configured. HttpOnly, Secure, and SameSite flags are set.'
                    elif 'samesite=none' in set_cookie.lower():
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'Critical'
                        set_cookie_solution = 'Strictly avoid using SameSite=None unless necessary, as it allows cross-site cookie usage. However, HttpOnly and Secure flags are set, which is good.'
                    else:
                        set_cookie_status = 'WARNING'
                        set_cookie_impact = 'High'
                        set_cookie_solution = 'None of the required flags are set for cookies. Consider setting SameSite attribute to Strict or Lax for cookies to enhance security.'
                        
                        
            access_control = headers.get('Access-Control-Allow-Origin', '')
            credentials = headers.get('Access-Control-Allow-Credentials', '')
            strip_access_control = access_control.strip()
            if strip_access_control == '*':
                access_control_status = 'WARNING'
                access_control_impact = 'High'
                access_control_solution = 'Avoid using wildcard (*) in Access-Control-Allow-Origin to prevent unauthorized cross-origin requests.'
                if credentials.lower() == 'true':
                    access_control_status = 'WARNING'
                    access_control_impact = 'High'
                    access_control_solution = 'Using wildcard (*) in Access-Control-Allow-Origin with Access-Control-Allow-Credentials set to true is a critical security risk. Avoid this configuration to prevent unauthorized cross-origin requests with credentials.'
            elif access_control and strip_access_control != 'null':
                access_control_status = 'SECURE'
                access_control_impact = 'Low'
                access_control_solution = f'Access-Control-Allow-Origin is set to {access_control}, which is good.'
            else:
                access_control_status = 'MISSING'
                access_control_impact = 'Medium'
                access_control_solution = 'Implement Access-Control-Allow-Origin to control cross-origin resource sharing.'
                
                
                
            clear_site_data = headers.get('Clear-Site-Data', '')
            if clear_site_data:
                clear_site_data_status = 'SECURE'
                clear_site_data_impact = 'Low'
                clear_site_data_solution = 'Clear-Site-Data is properly configured to enhance privacy and security.'
            else:
                clear_site_data_status = 'WARNING'
                clear_site_data_impact = 'Medium'
                clear_site_data_solution = 'Review Clear-Site-Data configuration to ensure it effectively protects user data.'
                
            coop = headers.get('Cross-Origin-Opener-Policy', '')
            
            if not coop:
                coop_status = 'MISSING'
                coop_impact = 'Medium'
                coop_solution = 'Implement Cross-Origin-Opener-Policy to enhance isolation and protect against cross-origin attacks.'
            elif 'same-origin-allow-popups' in coop.lower():
                coop_status = 'WARNING'
                coop_impact = 'Medium'
                coop_solution = 'Cross-Origin-Opener-Policy is set to same-origin-allow-popups, which may introduce security risks.'
            elif 'same-origin' in coop.lower():
                coop_status = 'SECURE'
                coop_impact = 'Low'
                coop_solution = 'Cross-Origin-Opener-Policy is properly configured.'
            else:
                coop_status = 'WARNING'
                coop_impact = 'Medium'
                coop_solution = 'Use same-origin for Cross-Origin-Opener-Policy to enhance security.'
            
            server_name = headers.get('Server', '')
            x_powered_by = headers.get('X-Powered-By', '')
            
            if not server_name:
                server_name_status = 'SECURE'
                server_name_impact = 'Low'
                server_name_solution = 'Server header is not present, which is good for security.'
            else:
                if re.search(r'\d', server_name):
                    server_name_status = 'WARNING'
                    server_name_impact = 'Medium'
                    server_name_solution = 'Avoid disclosing server version information in the Server header to reduce attack surface.'
                else:
                    server_name_status = 'SECURE'
                    server_name_impact = 'Low'
                    server_name_solution = 'Server header is present but does not disclose version information, which is good for security.'
                    
            if not x_powered_by:
                x_powered_by_status = 'SECURE'
                x_powered_by_impact = 'Low'
                x_powered_by_solution = 'X-Powered-By header is not present, which is good for security.'
            else:
                x_powered_by_status = 'WARNING'
                x_powered_by_impact = 'Medium'
                x_powered_by_solution = 'Avoid disclosing technology stack information in the X-Powered-By header to reduce attack surface.'
                    
                
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
                "referer_policy": {
                    "status": referer_policy_status,
                    "impact": referer_policy_impact,
                    "solution": referer_policy_solution
                },
                "set_cookie_for_httpOnly": {
                    "status": set_cookie_httpOnly_status,
                    "impact": set_cookie_httpOnly_impact,
                    "solution": set_cookie_httpOnly_solution
                },
                "set_cookie_for_secure": {
                    "status": set_cookie_secure_status,
                    "impact": set_cookie_secure_impact,
                    "solution": set_cookie_secure_solution
                },
                "set_cookie": {
                    "status": set_cookie_status,
                    "impact": set_cookie_impact,
                    "solution": set_cookie_solution
                },
                "permissions_policy": {
                    "status": permission_policy_status,
                    "impact": permission_policy_impact,
                    "solution": permission_policy_solution
                },
                "access_control_allow_origin": {
                    "status": access_control_status,
                    "impact": access_control_impact,
                    "solution": access_control_solution
                },
                "clear_site_data": {
                    "status": clear_site_data_status,
                    "impact": clear_site_data_impact,
                    "solution": clear_site_data_solution    
                },
                "coop": {
                    "status": coop_status,
                    "impact": coop_impact,
                    "solution": coop_solution
                },
                "server_name": {
                    "status": server_name_status,
                    "impact": server_name_impact,
                    "solution": server_name_solution
                },
                "x_powered_by": {
                    "status": x_powered_by_status,
                    "impact": x_powered_by_impact,
                    "solution": x_powered_by_solution
                },}, status=200)

        else:
            return Response({"error": "Invalid serializer data"}, status=400)