from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate

from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.validators import UniqueValidator

from .models import Profile

class RegisterSerializer(serializers.ModelSerializer) :
    email = serializers.EmailField(   #왜 얘는 modelserializer 인데 meta class 아래애 넣지 않고 정의했을까? -> 아마 여러 설정 필요해서? -> 그럼 아래 왜 또?
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],    
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    password2 = serializers.CharField(write_only=True, required= True)

    class Meta :
        model = User
        fields =('username', 'password', 'password2', 'email')
    
    def validate(self, data) :
        if data['password'] != data['password2'] :
            raise serializers.ValidationError(
                {"password": "Password fields didn,t match."})
        return data

    def create(self, validated_data) :   # 여기거 인수인 validated_date 는 갑자기 어디서 튀어나옴?
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
        )

        user.set_password(validated_data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return user

class LoginSerializer(serializers.Serializer) :
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user :
            token = Token.objects.get(user=user)
            return token
        raise serializers.ValidationError(
            {"error": "Unable to log in with provided credntials."}
        )

class ProfileSerializer(serializers.ModelSerializer):
    class Meta :
        model = Profile
        fields = ("nickname", "position", "subjects", "image")