from rest_framework.permissions import BasePermission


class IsNonAnonymousUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return request.user and not request.user.is_anonymous
