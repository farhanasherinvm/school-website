
from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser
from .serializers import UserSignupSerializer, OTPVerifySerializer, UserLoginSerializer,ResendOTPSerializer
import random
from django.utils import timezone
from datetime import timedelta

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



class ResendOTPView(generics.GenericAPIView):
    serializer_class = ResendOTPSerializer

    COOLDOWN_SECONDS = 60  # Cooldown second 

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({
               
                "message": "User not found.",
                "cooldown_remaining": 0
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if user is already verified
        if user.is_active:
            return Response({
                
                "message": "Account already verified.",
                "cooldown_remaining": 0
            }, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        cooldown_remaining = 0

        if user.otp_created_at:
            elapsed = (now - user.otp_created_at).total_seconds()
            cooldown_remaining = max(self.COOLDOWN_SECONDS - int(elapsed), 0)

        if cooldown_remaining > 0:
            return Response({
                
                "message": "Please wait before requesting a new OTP.",
                "cooldown_remaining": cooldown_remaining
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # Generate New OTP
        otp = f"{random.randint(100000, 999999)}"
        user.otp = otp
        user.otp_created_at = now
        user.save()

        # Send OTP via Email
        send_mail(
            subject="Your OTP Code (Resent)",
            message=f"Your new OTP is {otp}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email]
        )

        return Response({
            
            "message": "OTP has been resent to your email.",
            "cooldown_remaining": self.COOLDOWN_SECONDS
        }, status=status.HTTP_200_OK)
