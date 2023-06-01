from django.contrib.auth import authenticate
from django.contrib.auth.models import Permission

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework import status, viewsets

from users.serializer import *
from users.models import *
from users.custom_permission import is_permission,ISAllowed


class CreateUser(APIView):
    serializer_class = RegisterSerializer
    queryset = User.objects.all()

    def post(self, request):
        user_type = request.data.get('user_type')
        permissions = request.data.get('permissions')
        restaurant = request.data.get('restaurant')

        if is_permission(request.user, f'can_create_user_at_level{user_type}', restaurant, permissions=permissions):
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)

    def get(self, request):
        restaurants = request.user.restaurant.all()
        if is_permission(request.user, f'can_read_many_users', restaurants):
            queryset = self.queryset.filter(user_type__gt=request.user.user_type)

            serializer = self.serializer_class(queryset, many=True)
            return Response(serializer.data)


class UserView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, pk):
        # Check if a specific object is requested

        instance = self.queryset.filter(id=pk).last()
        user_type = instance.user_type
        res_id = instance.restaurants.all()
        if is_permission(request.user, f'read_user_at_level{user_type}', res_id):
            serializer = self.serializer_class(instance)
            return Response(serializer.data)

        # Retrieve multiple objects

    def patch(self, request, pk, *args, **kwargs):

        instance = self.queryset.filter(id=pk).last()
        permissions = request.data.get('permissions')
        user_type = instance.user_type
        if is_permission(request.user, f'update_user_at_level{user_type}', permissions):

            user_type_from_request = request.data.get('user_type')
            user_permission = f'update_user_at_level{user_type_from_request}'

            if user_type_from_request and user_permission not in str(request.user.permissions.all()):
                raise Exception("you do not have permission to perform this action")

        serializer = self.serializer_class(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=400)

    def delete(self, request, pk, *args, **kwargs):
        instance = self.queryset.filter(id=pk)
        res_id = instance.restaurants.all()
        user_type = instance.user_type
        if is_permission(request.user, f'delete_user_at_level{user_type}', res_id):
            serializer = self.serializer_class(instance)
            instance.delete()
            return Response(serializer.data)


class Login(APIView):
    serializer_class = UserSerializer

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(username=email, password=password)
        if user is None:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token = str(AccessToken.for_user(user))
        refresh_token = str(RefreshToken.for_user(user))
        serializer = self.serializer_class(user, data=request.data)
        serializer.is_valid()
        print(serializer.data)
        return Response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.email,
            "user_type": user.user_type,
            "permission": user.permissions.all().values_list("permission", flat=True)
        })


class AddRemovePermissions(APIView):
    serializer_class = UserSerializer

    def patch(self, request, pk):
        instance = User.objects.get(pk=pk)
        related_instance = Permission.objects.get(pk=request.permission)
        user_type = instance.user_type
        if is_permission(request.user, f'update_user_at_level{user_type}', request.permissions):
            if request.POST.get("action") == 'add':
                instance.permissions.add(related_instance)

            elif request.POST.get("action") == 'remove':
                instance.permissions.remove(related_instance)

            else:
                return Response({'error': 'Invalid action.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(instance)
        return Response(serializer.data)


class RestaurantsView(viewsets.ModelViewSet):
    queryset = Restaurants.objects.all()
    serializer_class = RestaurantSerializer
    permission_classes = [ISAllowed]
