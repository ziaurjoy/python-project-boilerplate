from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

from . import utils
from . import choose
from . import file_name
# Create your models here.


class UserManager(BaseUserManager):
    @transaction.atomic
    def create_user(self, email=None, phone=None, password=None, **extra_fields):
        if not email and not phone:
            raise ValueError('The Email or Phone number must be set')

        if email:
            email = self.normalize_email(email)

        user = self.model(email=email, phone=phone, **extra_fields)
        user.set_password(password)

        # Start transaction block
        with transaction.atomic():
            user.save(using=self._db)

            OTPVerify.objects.create(
                otp=utils.generate_otp(),
                expired=utils.expired_time(),
                user=user,
                email=user.email,
                phone=user.phone,
            )

            UserProfile.objects.create(user=user, email=user.email, phone=user.phone)

        return user

    @transaction.atomic
    def create_superuser(self, email=None, phone=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        user = self.create_user(email, phone, password, **extra_fields)
        
        return user



class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=15, unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'  # or 'phone' if you prefer phone as default
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email or self.phone



class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete = models.PROTECT)
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, choices=choose.gender)
    profile_picture = models.ImageField(null=True, blank=True, upload_to=file_name.profile_pictures)
    address = models.TextField(null=True, blank=True)
    
    def __str__(self):
        return self.first_name + self.last_name
    


class OTPVerify(models.Model):
    user=models.OneToOneField(User, on_delete=models.PROTECT)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=15, unique=True, null=True, blank=True)
    otp = models.CharField(max_length=4)
    is_verify = models.BooleanField(default=False)
    expired = models.DateTimeField()
    otp_type = models.CharField(max_length=20, choices=choose.otp_type, default='Registration')
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.email