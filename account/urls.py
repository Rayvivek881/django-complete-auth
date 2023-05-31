from django.urls import path
from account.views import *

urlpatterns = [
  path('register/', UserResgistrationView.as_view(), name='user-registration'),
  path('login/', UserLoginView.as_view(), name='user-login'),
  path('profile/', UserProfileView.as_view(), name='user-profile'),
  path('change/password/', UserChangePasswordView.as_view(), name='user-change-password'),
  path('send/resetpassword/email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
  path('resetpassword/<uid>/<token>/', UserPasswordResetView.as_view(), name='send-reset-password-email')
]