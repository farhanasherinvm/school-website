from django.urls import path
from .views import SignupView, OTPVerifyView, LoginView, ResendOTPView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('verify-otp/', OTPVerifyView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view()),
    path('login/', LoginView.as_view(), name='login'),
]
