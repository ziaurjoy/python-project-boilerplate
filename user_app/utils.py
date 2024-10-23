import os
import random
import string

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timedelta
import time
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import get_template
# from celery import shared_task

from rest_framework_simplejwt.tokens import RefreshToken

from . import models

def error_message(serializer):
    if type(serializer.errors['error']) == type([]):
        serializer_errors = serializer.errors
        for field_name, field_errors in serializer_errors.items():
            pass
        return {'message': field_errors[0]}

    return {'message': serializer.errors}


def generate_otp(length=int(os.environ.get('OTP_LENGHT'))):
    characters = string.digits
    otp = ''.join(random.choice(characters) for _ in range(length))
    return otp


# @shared_task
# def send_otp_email(email, otp):
#     # time.sleep(10)
#     subject = 'TOTO Deal OTP Verification Code'
#     from_email = os.environ.get('EMAIL_CONTACT')
#     domain = os.environ.get('BACKEND_DOMAIN')
#     context = {'email': email, 'opt': otp, 'domain': domain}
#     template = get_template('otp_verify/opt_verified.html').render(context)

#     return send_mail(
#         subject,
#         None, # Pass None because it's a HTML mail
#         from_email,
#         [email],
#         fail_silently=False,
#         html_message = template
#     )

def expired_time():
    now = datetime.today()
    result = now + timedelta(minutes=int(os.environ.get('OTP_VALIDATION_TIME')))
    return result


def google_login_response_data(user):
    data = {}
    refresh = RefreshToken.for_user(user)
    data['access'] = str(refresh.access_token)
    data['refresh'] = str(refresh)

    return data