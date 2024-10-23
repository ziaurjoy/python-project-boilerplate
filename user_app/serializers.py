
import datetime
from django.db.models import Q
from django.contrib.auth import authenticate

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from . import models



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ['email', 'phone', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        try:
            user = models.User.objects.create_user(**validated_data)
            return user
        except Exception as e:
            raise ValidationError({'error': str(e)})

    def to_internal_value(self, data):
        """
        Override to return all validation errors in the {'error': 'message'} format.
        """
        try:
            return super().to_internal_value(data)
        except ValidationError as exc:
            # Extract the first error message from the error details
            error_message = next(iter(exc.detail.values()))[0]
            raise ValidationError({'message': error_message.title()})
        


class SendOTPSerializer(serializers.Serializer):
    otp_identifier = serializers.CharField()

    def validate(self, data):
        otp_identifier = data.get('otp_identifier')

        get_otp_verify = models.OTPVerify.objects.filter(Q(email=otp_identifier) | Q(phone=otp_identifier)).exists()

        if get_otp_verify:
            return data
        else:
            raise serializers.ValidationError({"error": f"{otp_identifier} is not registered!"})



class OTPVerifySerializer(serializers.Serializer):
    otp_identifier = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, data):
        otp_identifier = data.get('otp_identifier')
        otp = data.get('otp')

        get_otp_verify = models.OTPVerify.objects.filter(
                (Q(email=otp_identifier) | Q(phone=otp_identifier)) & Q(otp=otp)
            ).first()

        if get_otp_verify:

            valided_time = get_otp_verify.expired

            _valided_time = datetime.datetime(
                valided_time.year, valided_time.month, valided_time.day, 
                valided_time.hour, valided_time.minute, valided_time.second
                ) 

            current_time = datetime.datetime.now()

            _current_time = datetime.datetime(
                current_time.year, current_time.month, current_time.day, 
                current_time.hour, current_time.minute, current_time.second
                )

            if _valided_time < _current_time:
                raise serializers.ValidationError({"error": "OTP expired!"})

            return data
        return data




class LoginSerializer(serializers.Serializer):
    login_identifier = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, data):
        login_identifier = data.get('login_identifier')
        password = data.get('password')

        user = None

        # Authenticate by email or phone
        if '@' in login_identifier:
            user = authenticate(email=login_identifier, password=password)
        else:
            user = authenticate(phone=login_identifier, password=password)

        if user is None or not user.is_active:
            # Return a string error message instead of a dict
            raise serializers.ValidationError({'error': 'No active account found with the given credentials'})

        data['user'] = user
        return data



class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confrim_password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        old_password = data.get('old_password')
        # Check the old password
        if not user.check_password(old_password):
            # Raise ValidationError in a global way, with "error" as the key
            raise serializers.ValidationError({"error": "Old password is not correct."})
        
        # Check if new password matches confirm password
        if data['new_password'] != data['confrim_password']:
            raise serializers.ValidationError({"error": "New and Confirm Password do not match."})
        
        # Ensure the new password is different from the old password
        if data['old_password'] == data['new_password']:
            raise serializers.ValidationError({"error": "New password must be different from the old password."})

        return data

    
    
class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    confrim_password = serializers.CharField(required=True)
    reset_identifier = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['confrim_password']:
            raise serializers.ValidationError({"error": "Password fields didn't match."})
        
        reset_identifier = attrs['reset_identifier']

        get_identifier_otp_verify = models.OTPVerify.objects.filter(Q(email=reset_identifier) | Q(phone=reset_identifier)).first()
        if get_identifier_otp_verify:
            if get_identifier_otp_verify.is_verify == False:
                raise serializers.ValidationError({"error": "OTP not verified !"})
            
            # valided_time = get_identifier_otp_verify.expired

            # _valided_time = datetime.datetime(
            #     valided_time.year, valided_time.month, valided_time.day, 
            #     valided_time.hour, valided_time.minute, valided_time.second
            #     ) 

            # current_time = datetime.datetime.now()

            # _current_time = datetime.datetime(
            #     current_time.year, current_time.month, current_time.day, 
            #     current_time.hour, current_time.minute, current_time.second
            #     )

            # if _valided_time < _current_time:
            #     raise serializers.ValidationError({"error": "OTP expired!"})
            

            _user = models.User.objects.get(Q(email=reset_identifier) | Q(phone=reset_identifier))
            _user.set_password(attrs['password'])
            _user.save()
            return attrs
        
        raise serializers.ValidationError({"error": "OTP not verified !"})