"""
URL configuration for restaurant_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework import routers
from users.views import *

router = routers.DefaultRouter()
router.register('permission', PermissionsView)
router.register('restaurant', RestaurantsView)
router.register('role', RoleView)

urlpatterns = [
                  path('admin/', admin.site.urls),
                  path('user/', CreateUser.as_view(), name='create_user'),
                  path('user/<int:pk>/', UserView.as_view(), name='user'),
                  path('login/', Login.as_view(), name='login'),
              ] + router.urls
