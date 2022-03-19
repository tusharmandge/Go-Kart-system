from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .chatbot import chatbot


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_exempt
def send_message(request):
    user_message = request.POST.get("user_message")

    if not user_message:
        return Response({'error': True, 'message': 'no message found!'})
    return Response({'error': False, 'message_response': str(chatbot.get_response(user_message))})
