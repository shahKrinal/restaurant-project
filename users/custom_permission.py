from rest_framework.permissions import BasePermission


def is_permission(user, user_permission, restaurant_ids, role=None, permissions=None):
    if user.is_superuser:
        return True
    else:
        if user_permission not in str(user.permissions.all()):
            return False

        if user.user_type == int(user_permission[-1]):

            if user.role and user.role.designation == 'Manager':
                pass
            elif user.role and user_permission.startswith("can_read"):
                if not user.role.designation == role.designation and user.role.position == 'Junior' and role.position == 'Senior':
                    return False
            else:
                if user.role and not user.role.designation == role.designation or user.role.position == role.position:
                    return False

        user_res = set(user.restaurant.values_list('id', flat='true'))
        res_ids = set(restaurant_ids)
        if user_res and res_ids and not res_ids.issubset(user_res):
            return False

        perm1 = set(user.permissions.values_list('id', flat='true'))
        perm2 = set([] if permissions is
                          None else [int(val) for val in permissions])
        if perm1 and perm2 and not perm2.issubset(perm1):
            return False

        return True


class ISAllowed(BasePermission):
    def has_permission(self, request, view):
        permission = 'can_create_or_access_restaurant'
        user_permission = request.user.permissions.all()
        if permission in str(user_permission):
            return True
