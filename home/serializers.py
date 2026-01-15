"""
Production-Ready Serializers
Clean serializers with NO permission logic
"""
from rest_framework import serializers
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
    Serializer for Document model (example resource).
    """
    owner = UserSerializer(read_only=True)
    
    class Meta:
        model = Document
        fields = ['id', 'title', 'content', 'owner', 'created_at', 'updated_at']
        read_only_fields = ['id', 'owner', 'created_at', 'updated_at']


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
    Serializer for creating edit requests.
    """
    document_id = serializers.IntegerField(required=True)
    new_title = serializers.CharField(required=True, max_length=255)
    new_content = serializers.CharField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True)


class ReviewEditRequestSerializer(serializers.Serializer):
    """
    Serializer for admin to review edit requests.
    """
    approve = serializers.BooleanField(required=True)
    review_comment = serializers.CharField(required=False, allow_blank=True)


class LoginSerializer(serializers.Serializer):
    """
    Serializer for login requests.
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change requests.
    """
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match")
        
        if len(data['new_password']) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        return data


class CreateUserSerializer(serializers.Serializer):
    """
    Serializer for creating new users (Admin only).
    """
    username = serializers.CharField(required=True, max_length=150)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=False, max_length=150)
    last_name = serializers.CharField(required=False, max_length=150)
    password = serializers.CharField(required=True, write_only=True, min_length=8)
    role = serializers.ChoiceField(choices=['editor', 'user'], required=True)
    
    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value


class UpdateUserRoleSerializer(serializers.Serializer):
    """
    Serializer for updating user roles (Admin only).
    """
    user_id = serializers.IntegerField(required=True)
    role = serializers.ChoiceField(choices=['admin', 'editor', 'user'], required=True)


class AssignUserToOrganizationSerializer(serializers.Serializer):
    """
    Serializer for assigning users to organizations (Admin only).
    """
    user_id = serializers.IntegerField(required=True)
    role = serializers.ChoiceField(choices=['admin', 'editor', 'user'], required=True)
