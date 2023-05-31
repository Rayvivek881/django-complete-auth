from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import authenticate

from account.serializers import *
from account.randerors import UserRenderers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
    'refresh': str(refresh),
    'access': str(refresh.access_token)
  }

def ResponseError(message):
  return Response(message, status=status.HTTP_400_BAD_REQUEST)

class UserResgistrationView(APIView):
  renderer_classes = [UserRenderers]
  def post(self, request, format=None):
    serializer = UserResgistrationSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      user = serializer.save()
      return Response({
        'data' : serializer.data,
        'message' : 'User created successfully'
      }, status=status.HTTP_201_CREATED)
    
    return ResponseError(serializer.errors)

class UserLoginView(APIView):
  
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      user = authenticate(email=serializer.data['email'], password=serializer.data['password'])
      if user is None:
        return ResponseError({'value': 'Please enter correct creadentials'})
      return Response({
        'data' : serializer.data,
        'message' : 'User logged in successfully',
        'tokens' : get_tokens_for_user(user)
      }, status=status.HTTP_200_OK)
    
    return ResponseError(serializer.errors)

class UserProfileView(APIView):
  renderer_classes = [UserRenderers]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response({
      'data' : serializer.data,
      'message' : 'User profile fetched successfully'
    }, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderers]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerilizer(data=request.data, context = { 'user': request.user })
    if serializer.is_valid(raise_exception=True):
      return Response({
        'data' : serializer.data,
        'message' : 'User password changed successfully',
      }, status=status.HTTP_200_OK)
    
    return ResponseError(serializer.errors)
  

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderers]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      return Response({
        'data' : serializer.data,
        'message' : 'Password reset email sent successfully',
      }, status=status.HTTP_200_OK)
    
    return ResponseError(serializer.errors)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderers]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
    if serializer.is_valid(raise_exception=True):
      return Response({
        'data' : serializer.data,
        'message' : 'Password reset successfully',
      }, status=status.HTTP_200_OK)
    
    return ResponseError(serializer.errors)