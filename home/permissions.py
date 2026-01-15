from rest_framework import permissions
from .services import AuthorizationService
from .models import Role


class HasPermission(permissions.BasePermission):
    """
    Base permission class that checks if user has a specific permission.
    
    Usage in ViewSet:
        permission_classes = [HasPermission]
        required_permission = 'read'  # or 'create', 'update', 'delete'
    """
    
    def has_permission(self, request, view):
        # User must be authenticated
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Get required permission from view
        permission_name = getattr(view, 'required_permission', None)
        if not permission_name:
            return False
        
        # Check permission via service
        return AuthorizationService.has_permission(request.user, permission_name)


class CanCreateResource(permissions.BasePermission):
    """
    Permission class for CREATE operations.
    Checks if user has 'create' permission.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return AuthorizationService.has_permission(request.user, 'create')


class CanReadResource(permissions.BasePermission):
    """
    Permission class for READ operations.
    Checks if user has 'read' permission.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return AuthorizationService.has_permission(request.user, 'read')


class CanModifyResource(permissions.BasePermission):
    """
    Permission class for UPDATE/DELETE operations.
    
    - Admins can modify any resource directly
    - Editors CANNOT modify directly (must use edit requests)
    - Users cannot modify at all
    """
    
    def has_permission(self, request, view):
        # Basic authentication check
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Determine permission based on method
        if request.method in ['PUT', 'PATCH']:
            permission_name = 'update'
        elif request.method == 'DELETE':
            permission_name = 'delete'
        else:
            return False
        
        # Only admins can directly modify documents
        # Editors must use edit request workflow
        return AuthorizationService.is_admin(request.user)
    
    def has_object_permission(self, request, view, obj):
        """
        Object-level permission check.
        Only admins can directly modify documents.
        """
        # Determine permission based on method
        if request.method in ['PUT', 'PATCH']:
            permission_name = 'update'
        elif request.method == 'DELETE':
            permission_name = 'delete'
        else:
            return False
        
        # Only admins can directly modify
        return AuthorizationService.is_admin(request.user)


class IsAdmin(permissions.BasePermission):
    """
    Permission class that only allows Admins.
    Used for user management endpoints.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return AuthorizationService.is_admin(request.user)


class CanManageUsers(permissions.BasePermission):
    """
    Permission class for user management operations.
    Only Admins can manage users.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return AuthorizationService.can_manage_users(request.user)
