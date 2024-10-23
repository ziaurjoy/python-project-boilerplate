import requests
from django.db.models import Q
from django.db import transaction, IntegrityError

from rest_framework import status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from . import utils
from . import serializers
from . import models

# Create your views here.



class RegisterUserView(views.APIView):
    def post(self, request):
        serializer = serializers.UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Registration completed successfully'}, status=status.HTTP_201_CREATED)
        
        return Response(utils.error_message(serializer), status=status.HTTP_400_BAD_REQUEST)
        



class SendOTP(views.APIView):

    def post(self, request):
        
        otp_identifier = request.data['otp_identifier']
        otp_record = models.OTPVerify.objects.filter(Q(email=otp_identifier) | Q(phone=otp_identifier)).first()
        serializer = serializers.SendOTPSerializer(data=request.data)

        if serializer.is_valid() and otp_record:
            try:
                with transaction.atomic():
                    # Mark OTP as verified
                    otp_record.is_verify = False
                    otp_record.otp = utils.generate_otp()
                    otp_record.expired = utils.expired_time()
                    otp_record.otp_type = 'Reset Password'
                    otp_record.save()

                    # utils.send_otp_email.delay(email, new_otp)

                return Response({'message': f'Send OTP to {otp_identifier}'}, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(utils.error_message(serializer), status=status.HTTP_400_BAD_REQUEST)
    



class VerifyOTP(views.APIView):

    def post(self, request):

        serializer = serializers.OTPVerifySerializer(data=request.data)
        
        if serializer.is_valid():
            otp_identifier = serializer.validated_data.get('otp_identifier')
            otp = serializer.validated_data.get('otp')

            # Check if OTP matches for either email or phone
            otp_record = models.OTPVerify.objects.filter(
                (Q(email=otp_identifier) | Q(phone=otp_identifier)) & Q(otp=otp)
            ).first()

            if otp_record:
                try:
                    with transaction.atomic():
                        # Mark OTP as verified
                        otp_record.is_verify = True
                        otp_record.save()

                        # Activate user account if exists
                        models.User.objects.filter(email=otp_identifier).update(is_active=True)

                    return Response({'message': 'OTP verified'}, status=status.HTTP_200_OK)

                except Exception as e:
                    return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'message': "OTP does not match."}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(utils.error_message(serializer), status=status.HTTP_400_BAD_REQUEST)




class LoginView(views.APIView):
    def post(self, request):
        serializer = serializers.LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        
        return Response(utils.error_message(serializer), status=status.HTTP_400_BAD_REQUEST)




class ChangePasswordView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = serializers.ChangePasswordSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)

        return Response(utils.error_message(serializer), status=status.HTTP_400_BAD_REQUEST)
    




class ResetPasswordView(views.APIView):

    def post(self, request, format=None):
        serializer = serializers.ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Reset Password Successfuly Done'}, status=status.HTTP_201_CREATED)
 
        return Response(utils.error_message(serializer), status=status.HTTP_400_BAD_REQUEST)





class GoogleRedirectURIView(views.APIView):
    
    def get(self, request):
        access_token = request.GET.get('access_token')
        if access_token:

            # Make a request to fetch the user's profile information
            profile_endpoint = 'https://www.googleapis.com/oauth2/v1/userinfo'
            headers = {'Authorization': f'Bearer {access_token}'}
            profile_response = requests.get(profile_endpoint, headers=headers)
            
            if profile_response.status_code == 200:
                profile_data = profile_response.json()

                if models.User.objects.filter(email=profile_data["email"]).exists():
                    user = models.User.objects.get(email=profile_data["email"])
                    data = utils.google_login_response_data(user)

                    return Response(data, status.HTTP_201_CREATED)
                
                try:
                    with transaction.atomic():
                        # Proceed with user creation or login
                        user = models.User.objects.create(
                            email=profile_data["email"],
                            is_active=True,
                            )
                        
                        models.UserProfile.objects.create(
                            user=user,
                            first_name=profile_data["given_name"],
                            last_name=profile_data["family_name"] if 'family_name' in profile_data.keys() else '',
                            email=user.email,
                            profile_picture=profile_data["picture"],

                        )
                        data = utils.google_login_response_data(user)

                        return Response(data, status.HTTP_201_CREATED)

                except IntegrityError as err:
                    return Response({'message': str(err)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Access Token Not Found'}, status.HTTP_400_BAD_REQUEST)
    
