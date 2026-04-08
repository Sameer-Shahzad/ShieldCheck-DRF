from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.throttling import UserRateThrottle
# Create your views here.


class scanView(APIView):
    throttle_classes = [UserRateThrottle]
    
    def post (self, request):
        url = request.data.get('url')
        if url.is_valid():
            return render ('scan_result.html', {'url': url})