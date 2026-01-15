from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Each user has a single role assigned directly.
    """
    force_password_change = models.BooleanField(default=False)
    is_default_admin = models.BooleanField(default=False)  # Flag for default admin account
    role = models.ForeignKey('Role', on_delete=models.SET_NULL, null=True, blank=True, related_name='users')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users'
        indexes = [
            models.Index(fields=['username']),
            models.Index(fields=['email']),
            models.Index(fields=['role']),
        ]

    def __str__(self):
        return self.username


class Role(models.Model):
    """
    Database-driven roles. Permissions are assigned to roles dynamically.
    Roles: Admin, Editor, User
    """
    ADMIN = 'admin'
    EDITOR = 'editor'
    USER = 'user'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (EDITOR, 'Editor'),
        (USER, 'User'),
    ]

    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'roles'
        indexes = [
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return self.get_name_display()


class Permission(models.Model):
    """
    Database-driven permissions.
    Actions: create, read, update, delete
    """
    CREATE = 'create'
    READ = 'read'
    UPDATE = 'update'
    DELETE = 'delete'

    PERMISSION_CHOICES = [
        (CREATE, 'Create'),
        (READ, 'Read'),
        (UPDATE, 'Update'),
        (DELETE, 'Delete'),
    ]

    name = models.CharField(max_length=50, choices=PERMISSION_CHOICES, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'permissions'
        indexes = [
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return self.get_name_display()


class RolePermission(models.Model):
    """
    Many-to-Many relationship between Roles and Permissions.
    Editable at runtime - no hard-coded permission logic.
    """
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='permission_roles')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'role_permissions'
        unique_together = ('role', 'permission')
        indexes = [
            models.Index(fields=['role', 'permission']),
        ]

    def __str__(self):
        return f"{self.role.name} - {self.permission.name}"


class Document(models.Model):
    """
    Example resource for demonstrating RBAC.
    Each document has an owner.
    Only admins can directly edit documents.
    Editors must submit edit requests for approval.
    """
    title = models.CharField(max_length=255)
    content = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_documents')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'documents'
        indexes = [
            models.Index(fields=['owner']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.title


class DocumentEditRequest(models.Model):
    """
    Stores edit requests from editors that need admin approval.
    Editors cannot directly edit documents - they submit requests.
    Admins review and approve/reject these requests.
    """
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
    ]
    
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='edit_requests')
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='edit_requests')
    new_title = models.CharField(max_length=255)
    new_content = models.TextField()
    reason = models.TextField(blank=True, help_text='Reason for the edit')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_requests')
    review_comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'document_edit_requests'
        indexes = [
            models.Index(fields=['document', 'status']),
            models.Index(fields=['requested_by']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"Edit request for '{self.document.title}' by {self.requested_by.username} - {self.status}"


