from django.contrib import admin

# Register your models here.
from authapp.models import UserProfileInfo, User
admin.site.register(UserProfileInfo)