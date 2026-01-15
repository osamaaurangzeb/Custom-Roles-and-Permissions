"""
Django Admin Configuration for RBAC Models
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Role, Permission, RolePermission, Document, DocumentEditRequest


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['username', 'email', 'role', 'is_active', 'force_password_change', 'is_default_admin']
    list_filter = ['is_active', 'force_password_change', 'is_default_admin', 'role']
    fieldsets = BaseUserAdmin.fieldsets + (
        ('RBAC Fields', {'fields': ('role', 'force_password_change', 'is_default_admin')}),
    )


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'created_at']
    search_fields = ['name']


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'created_at']
    search_fields = ['name']


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ['role', 'permission', 'created_at']
    list_filter = ['role', 'permission']


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['title', 'owner', 'created_at']
    list_filter = ['created_at']
    search_fields = ['title', 'content']


@admin.register(DocumentEditRequest)
class DocumentEditRequestAdmin(admin.ModelAdmin):
    list_display = ['document', 'requested_by', 'status', 'reviewed_by', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['document__title', 'requested_by__username']
    readonly_fields = ['created_at', 'reviewed_at']
