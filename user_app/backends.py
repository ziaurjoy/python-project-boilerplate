from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailOrPhoneBackend(BaseBackend):
    def authenticate(self, request, email=None, phone=None, password=None, **kwargs):
        try:
            if email:
                user = User.objects.get(email=email)
            elif phone:
                user = User.objects.get(phone=phone)
            else:
                return None

            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
