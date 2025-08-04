
from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser
from .serializers import UserSignupSerializer, OTPVerifySerializer, UserLoginSerializer
import random

class SignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        otp = f"{random.randint(100000, 999999)}"
        user.otp = otp
        user.save()
        
        send_mail(
            subject="Your OTP Code",
            message=f"Your OTP is {otp}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email]
        )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({"message": "OTP has been sent to your email address."}, status=status.HTTP_201_CREATED)


class OTPVerifyView(generics.GenericAPIView):
    serializer_class = OTPVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        try:
            user = CustomUser.objects.get(email=email, otp=otp)
            user.is_active = True
            user.otp = ''
            user.save()
            return Response({"message": "Account verified successfully."})
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid OTP or Email"}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(request, email=email, password=password)
        if user is not None:
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            else:
                return Response({"error": "Account not verified."}, status=status.HTTP_403_FORBIDDEN)
        return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
