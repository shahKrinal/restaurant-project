from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from users.models import *


class PermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permissions
        fields = ("permission",)


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ("designation", "position")


class UserSerializer(serializers.ModelSerializer):
    role = RoleSerializer(read_only=True)
    permissions = PermissionsSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = (
            "email",
            "first_name",
            "last_name",
            "role",
            "user_type",
            "permissions",
            "restaurant",
        )


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True, validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    password2 = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = (
            "email",
            "first_name",
            "last_name",
            "password",
            "password2",
            "role",
            "user_type",
            "permissions",
            "restaurant",
        )

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            # username=validated_data['username'],
            email=validated_data.get("email"),
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
            role=validated_data.get("role") if validated_data.get("role") else None,
            user_type=validated_data.get("user_type"),
        )
        user.restaurant.set(validated_data["restaurant"])
        user.permissions.set(validated_data["permissions"])
        user.set_password(validated_data["password"])
        user.save()
        return user


class RestaurantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Restaurants
        fields = "__all__"
