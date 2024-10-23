
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views

urlpatterns = [
    # path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', views.RegisterUserView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('otp-verified/', views.VerifyOTP.as_view(), name='otp-verified'),
    path('send-otp/', views.SendOTP.as_view(), name='otp-verified'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('profile-update/', views.ProfileUpdateApiView.as_view(), name='reset-password'),

]
