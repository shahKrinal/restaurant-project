from django.contrib.auth import authenticate
from django.contrib.auth.models import Permission
from django.db.models import Q, Count, F
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAdminUser

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework import status, viewsets, generics
from rest_framework import mixins
from users.serializer import *
from users.models import *
from users.custom_permission import is_permission, ISAllowed
from users.custom_mixin import DeleteMixin, RetrieveMixin, RetrievedMixin, DestroyMixin


# from users.tests import CustomMixin


class CreateUser(APIView):
    serializer_class = RegisterSerializer
    queryset = User.objects.all()

    def post(self, request):
        user_type = request.data.get('user_type')
        permissions = request.data.get('permissions')
        restaurant = request.data.get('restaurant')
        role = Role.objects.get(id=request.data.get('role'))
        if is_permission(request.user, f'can_create_user_at_level{user_type}', restaurant, role=role,
                         permissions=permissions):

            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=400)
        return Response({"status": False, "message": "You do not have permission to perform this action"}, status=403)

    def get(self, request):
        restaurants = request.user.restaurant.values_list('id', flat='true')
        queryset = self.queryset.filter(user_type__gt=request.user.user_type, restaurant__in=restaurants)
        if request.user.role.position == 'Senior':
            queryset = queryset | User.objects.filter(Q(user_type=request.user.user_type, role__position='junior'))
        serializer = self.serializer_class(queryset, many=True)

        return Response(serializer.data)


class UserView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, pk):
        # Check if a specific object is requested

        instance = self.queryset.filter(id=pk).annotate(permission_count=Count('permissions', distinct=True),
                                                        role_count=Count('role', distinct=True)).last()
        user_type = instance.user_type

        res_id = instance.restaurant.values_list('id', flat='true')
        role = instance.role
        if is_permission(request.user, f'read_user_at_level_{user_type}', res_id, role=role):
            serializer = self.serializer_class(instance).data
            serializer['permission_count'] = instance.permission_count
            serializer['role_count'] = instance.role_count
            return Response(serializer)
        return Response({"status": False, "message": "You do not have permission to perform this action"}, status=403)

        # Retrieve multiple objects

    def patch(self, request, pk, *args, **kwargs):

        instance = self.queryset.filter(id=pk).last()
        permissions = request.data.get('permissions')
        user_type = instance.user_type
        role = instance.role
        restaurant = instance.restaurant.values_list('id', flat='true')
        if is_permission(request.user, f'update_user_at_level{user_type}', restaurant, role, permissions):

            user_type_from_request = request.data.get('user_type')
            user_permission = f'update_user_at_level{user_type_from_request}'

            if user_type_from_request and user_permission not in str(request.user.permissions.all()):
                raise Exception("you do not have permission to perform this action")

            if request.data.get('role'):
                role = Role.objects.get(id=request.data.get('role'))
                if not is_permission(request.user, f'can_create_user_at_level{user_type}', restaurant, role=role,
                                     permissions=permissions):
                    return Response("You do not have permission to perform this action", status=403)

            if request.data.get('restaurant'):
                restaurant = request.data.get('restaurant')
                if not is_permission(request.user, f'can_create_user_at_level{user_type}', restaurant, role=role,
                                     permissions=permissions):
                    return Response("You do not have permission to perform this action", status=403)

            serializer = self.serializer_class(instance, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=400)

        return Response({"status": False, "message": "You do not have permission to perform this action"}, status=403)

    def delete(self, request, pk, *args, **kwargs):
        instance = self.queryset.filter(id=pk).last()
        res_id = instance.restaurant.values_list('id', flat='true')
        user_type = instance.user_type
        role = instance.role
        if is_permission(request.user, f'delete_user_at_level{user_type}', res_id, role=role):
            serializer = self.serializer_class(instance)
            instance.delete()
            return Response(serializer.data)

        return Response({"status": False, "message": "You do not have permission to perform this action"}, status=403)


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

        return Response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.email,
            "user_type": user.user_type,
            "role": user.role.id,
            "restaurant": user.restaurant.values_list("restaurant_name", flat=True),
            "permission": user.permissions.values_list("permission", flat=True)
        })


class AddRemovePermissions(APIView):
    serializer_class = UserSerializer

    def patch(self, request, pk):
        instance = User.objects.get(pk=pk)
        related_instance = Permission.objects.get(pk=request.permission)
        user_type = instance.user_type
        role = instance.role
        res_ids = instance.restaurant.all()
        if is_permission(request.user, f'update_user_at_level{user_type}', res_ids, role=role,
                         permissions=request.permissions):
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


class RoleView(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAdminUser]


class PermissionsView(viewsets.ModelViewSet):
    queryset = Permissions.objects.all()
    serializer_class = PermissionsSerializer
    permission_classes = [IsAdminUser]


class CreateListView(mixins.ListModelMixin, mixins.CreateModelMixin, generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        # Handle GET request
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Handle POST request
        return self.create(request, *args, **kwargs)


class UsersView(DeleteMixin, RetrieveMixin, APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, pk, *args, **kwargs):
        return self.retrieve(request, pk, *args, **kwargs)

    def delete(self, request, pk, *args, **kwargs):
        return self.delete(request, pk, *args, **kwargs)


class RetrievedDeleteView(RetrieveMixin, DestroyMixin, generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)
