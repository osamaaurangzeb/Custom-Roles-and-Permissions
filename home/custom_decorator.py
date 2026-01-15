
from rest_framework.permissions import BasePermission
from functools import wraps
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseForbidden
from rest_framework.response import Response
from django.core.cache import cache
from .models import *


def check_seller_permission(method, model):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            
            print(request.user.role)
            if request.user.role == "doctor":
                return view_func(self, request, *args, **kwargs)
            
            user_permissions = set()
            for perm in request.user.get_all_permissions():
                user_permissions.add(perm)

            if method == 'GET':
                permission = f'{model._meta.app_label}.view_{model._meta.model_name}'
            elif method == 'POST':
                permission = f'{model._meta.app_label}.add_{model._meta.model_name}'
            elif method == 'PUT' or method == "PATCH":
                permission = f'{model._meta.app_label}.change_{model._meta.model_name}'
            elif method == 'DELETE':
                permission = f'{model._meta.app_label}.delete_{model._meta.model_name}'
            else:
                return Response({"detail": "Unsupported method"}, status=403)

            print(user_permissions)
            if permission in user_permissions:
                return view_func(self, request, *args, **kwargs)
            else:
                raise PermissionDenied("You don't have permission to access this page.")
          
            return view_func(self, request, *args, **kwargs)
        return _wrapped_view
    return decorator