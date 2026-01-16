"""
Production-Ready Serializers
Clean serializers with input validation and sanitization
"""
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.html import escape
import re
from .models import User, Role, Document, DocumentEditRequest


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model.
    Does not expose sensitive fields like password.
    """
    role_name = serializers.CharField(source='role.name', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'is_active', 'force_password_change', 'role_name', 'created_at']
        read_only_fields = ['id', 'created_at']


class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer for Role model.
    """
    class Meta:
        model = Role
        fields = ['id', 'name', 'description']
        read_only_fields = ['id']


class DocumentSerializer(serializers.ModelSerializer):
    """
    Serializer for Document model with input sanitization.
    """
    owner = UserSerializer(read_only=True)
    
    class Meta:
        model = Document
        fields = ['id', 'title', 'content', 'owner', 'created_at', 'updated_at']
        read_only_fields = ['id', 'owner', 'created_at', 'updated_at']
    
    def validate_title(self, value):
        """Sanitize and validate title"""
        if len(value) > 255:
            raise serializers.ValidationError("Title must be 255 characters or less")
        return escape(value.strip())
    
    def validate_content(self, value):
        """Sanitize content"""
        return escape(value.strip()) if value else ''


class DocumentEditRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for DocumentEditRequest model.
    Used by editors to submit edit requests.
    """
    requested_by = UserSerializer(read_only=True)
    reviewed_by = UserSerializer(read_only=True)
    document_title = serializers.CharField(source='document.title', read_only=True)
    
    class Meta:
        model = DocumentEditRequest
        fields = [
            'id', 'document', 'document_title', 'requested_by', 
            'new_title', 'new_content', 'reason', 'status',
            'reviewed_by', 'review_comment', 'created_at', 'reviewed_at'
        ]
        read_only_fields = ['id', 'requested_by', 'status', 'reviewed_by', 'review_comment', 'created_at', 'reviewed_at']


class CreateEditRequestSerializer(serializers.Serializer):
    """
    Serializer for creating edit requests with input sanitization.
    """
    document_id = serializers.IntegerField(required=True, min_value=1)
    new_title = serializers.CharField(required=True, max_length=255)
    new_content = serializers.CharField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True, max_length=1000)
    
    def validate_new_title(self, value):
        return escape(value.strip())
    
    def validate_new_content(self, value):
        return escape(value.strip())
    
    def validate_reason(self, value):
        return escape(value.strip()) if value else ''


class ReviewEditRequestSerializer(serializers.Serializer):
    """
    Serializer for admin to review edit requests.
    """
    approve = serializers.BooleanField(required=True)
    review_comment = serializers.CharField(required=False, allow_blank=True, max_length=1000)
    
    def validate_review_comment(self, value):
        return escape(value.strip()) if value else ''


class LoginSerializer(serializers.Serializer):
    """
    Serializer for login requests.
    """
    username = serializers.CharField(required=True, max_length=150)
    password = serializers.CharField(required=True, write_only=True, max_length=128)
    
    def validate_username(self, value):
        """Validate username format"""
        if not re.match(r'^[\w.@+-]+$', value):
            raise serializers.ValidationError("Invalid username format")
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change requests with validation.
    """
    old_password = serializers.CharField(required=True, write_only=True, max_length=128)
    new_password = serializers.CharField(required=True, write_only=True, max_length=128)
    confirm_password = serializers.CharField(required=True, write_only=True, max_length=128)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match")
        
        # Use Django's password validators
        try:
            validate_password(data['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': list(e.messages)})
        
        return data


class CreateUserSerializer(serializers.Serializer):
    """
    Serializer for creating new users (Admin only) with strong validation.
    """
    username = serializers.CharField(required=True, max_length=150)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=False, max_length=150, allow_blank=True)
    last_name = serializers.CharField(required=False, max_length=150, allow_blank=True)
    password = serializers.CharField(required=True, write_only=True, max_length=128)
    role = serializers.ChoiceField(choices=['editor', 'user'], required=True)
    
    def validate_username(self, value):
        """Validate username format and uniqueness"""
        if not re.match(r'^[\w.@+-]+$', value):
            raise serializers.ValidationError("Username can only contain letters, numbers, and @/./+/-/_")
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value
    
    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value.lower()
    
    def validate_password(self, value):
        """Validate password strength"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value
    
    def validate_first_name(self, value):
        return escape(value.strip()) if value else ''
    
    def validate_last_name(self, value):
        return escape(value.strip()) if value else ''


class UpdateUserRoleSerializer(serializers.Serializer):
    """
    Serializer for updating user roles (Admin only).
    """
    user_id = serializers.IntegerField(required=True, min_value=1)
    role = serializers.ChoiceField(choices=['admin', 'editor', 'user'], required=True)


class AssignUserToOrganizationSerializer(serializers.Serializer):
    """
    Serializer for assigning users to organizations (Admin only).
    """
    user_id = serializers.IntegerField(required=True, min_value=1)
    role = serializers.ChoiceField(choices=['admin', 'editor', 'user'], required=True)
