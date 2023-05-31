from rest_framework import serializers
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserResgistrationSerializer(serializers.ModelSerializer):
  password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

  class Meta:
    model = User
    fields = ('id', 'email', 'name', 'tc', 'password', 'password2')
    extra_kwargs = {'password': {'write_only': True}}

  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError({'password': 'Password fields didn\'t match'})
    return attrs

  def create(self, validated_data : dict):
    password = validated_data.pop('password2', None)
    instance = self.Meta.model(**validated_data)
    if password is not None:
      instance.set_password(password)
    instance.save()
    return instance

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=60)

  class Meta:
    model = User
    fields = ('email', 'password')

class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ('id', 'email', 'name', 'tc', 'is_admin')

class UserChangePasswordSerilizer(serializers.Serializer):
  password = serializers.CharField(required=True)
  password2 = serializers.CharField(required=True)
  class Meta:
    model = User
    fields = ('password', 'password2')

  def validate(self, attrs):
    user = self.context.get('user')
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError({'password': 'Password fields didn\'t match'})
    user.set_password(attrs['password'])
    user.save()
    return attrs
  
class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ('email')  
  def validate(self, attrs):
    if (not User.objects.filter(email=attrs['email']).exists()):
      raise serializers.ValidationError({'email': 'User not found'})
    user = User.objects.get(email=attrs['email'])
    uid, token = urlsafe_base64_encode(force_bytes(user.pk)), PasswordResetTokenGenerator().make_token(user)
    link = 'http://localhost:3000/reset-password/' + uid + '/' + token
    data = {
      'subject' : "Reset your password",
      'body' : "click " + link,
      'to_email' : user.email
    }
    return attrs

class UserPasswordResetSerializer(serializers.Serializer):
  class Meta:
    model = User
    fields = ('password', 'password2')

  def validate(self, attrs):
    password, password2 = attrs['password'], attrs['password2']
    uid, token = self.context.get('uid'), self.context.get('token')
    if password != password2:
      raise serializers.ValidationError({'password': 'Password fields didn\'t match'})
    id = smart_str(urlsafe_base64_decode(uid))
    user = User.objects.get(pk=id)
    if not PasswordResetTokenGenerator().check_token(user, token):
      raise serializers.ValidationError({'token': 'Invalid token'})
    user.set_password(password)
    user.save()
    return attrs
