from django.db import models

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models


# Create your models here.
class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, first_name, last_name, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
    """
        if not email:
            raise ValueError("The email must be set")
        first_name = first_name.capitalize()
        last_name = last_name.capitalize()
        email = self.normalize_email(email)

        user = self.model(
            first_name=first_name, last_name=last_name, email=email, **extra_fields
        )
        # user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user

    def create_superuser(self, first_name, last_name, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        if User.objects.filter(is_superuser=True).exists():
            raise Exception('A superuser already exists. The createsuperuser command is disabled.')
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(first_name, last_name, email, password, **extra_fields)


User_types = (
    (1, 'System_Admin'), (2, 'SYSTEM_STAFF'), (3, 'CLIENT_ADMIN'), (4, 'CLIENT_STAFF'), (5, 'CLIENT_CUSTOMERS'))


class Permissions(models.Model):
    permission = models.CharField(max_length=50)

    def __str__(self):
        return self.permission


class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    role = models.CharField(max_length=100,null=True)
    user_type = models.IntegerField(
        choices=User_types, null=True, blank=True)
    permissions = models.ManyToManyField(Permissions, blank=True)
    restaurant = models.ManyToManyField("Restaurants")
    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    def __str__(self):
        return self.email


class Restaurants(models.Model):
    restaurant_name = models.CharField(max_length=100)

