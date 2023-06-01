from rest_framework.permissions import BasePermission


def is_permission(user, user_permission, restaurant_ids, permissions=None):
    if user.is_superuser:
        return True
    else:
        if user_permission not in str(user.permissions.all()):
            raise Exception("you do not have permission to perform this action")

        user_res = set(user.restaurant.values_list('id', flat='true'))
        if user_res and restaurant_ids and not restaurant_ids.issubset(user_res):
            raise Exception("you do not have permission to perform this action")

        perm1 = set(user.permissions.values_list('id', flat='true'))
        perm2 = set([] if permissions is
                          None else [int(val) for val in permissions])
        if perm1 and perm2 and not perm2.issubset(perm1):
            raise Exception("you do not have permission to assign this permission")

        return True


class ISAllowed(BasePermission):
    def has_permission(self, request, view):
        permission = 'can_create_or_access_restaurant'
        user_permission = request.user.permissions.all()
        if permission in str(user_permission):
            return True
