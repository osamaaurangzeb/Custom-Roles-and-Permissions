from typing import Optional
from django.db.models import Q
from django.utils import timezone
from .models import User, Role, Permission, RolePermission, Document, DocumentEditRequest


class AuthorizationService:
    """
    Centralized service for all authorization decisions.
    Implements business rules for RBAC with ownership checks.
    """
    
    @staticmethod
    def has_permission(user: User, permission_name: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user: The user to check
            permission_name: Permission name (create, read, update, delete)
        
        Returns:
            bool: True if user has permission, False otherwise
        """
        if not user or not user.role:
            return False
        
        try:
            # Check if role has this permission
            has_perm = RolePermission.objects.filter(
                role=user.role,
                permission__name=permission_name
            ).exists()
            
            return has_perm
            
        except Exception:
            return False
    
    @staticmethod
    def is_admin(user: User) -> bool:
        """
        Check if user is an Admin.
        Admins have special privileges like overriding ownership rules.
        """
        if not user or not user.role:
            return False
        return user.role.name == Role.ADMIN
    
    @staticmethod
    def can_modify_resource(user: User, resource, permission_name: str) -> bool:
        """
        Check if user can modify a specific resource.
        Implements ownership rules:
        - Admins can modify any resource
        - Editors/Users can only modify resources they own
        
        Args:
            user: The user attempting the action
            resource: The resource object (must have 'owner' attribute)
            permission_name: Permission name (update or delete)
        
        Returns:
            bool: True if user can modify, False otherwise
        """
        # First check if user has the permission at all
        if not AuthorizationService.has_permission(user, permission_name):
            return False
        
        # Admin can modify any resource
        if AuthorizationService.is_admin(user):
            return True
        
        # Non-admins can only modify resources they own
        if hasattr(resource, 'owner'):
            return resource.owner == user
        
        return False
    
    @staticmethod
    def get_user_role(user: User) -> Optional[Role]:
        """
        Get user's role.
        """
        return user.role if user else None
    
    @staticmethod
    def can_manage_users(user: User) -> bool:
        """
        Check if user can manage other users (create, update, delete, assign roles).
        Only Admins can manage users.
        """
        return AuthorizationService.is_admin(user)
    
    @staticmethod
    def filter_accessible_documents(user: User, queryset):
        """
        Filter documents based on user's access rights.
        - Admins see all documents
        - Editors/Users see only their own documents
        
        Args:
            user: The user requesting documents
            queryset: Base queryset to filter
        
        Returns:
            Filtered queryset
        """
        # Admin sees all documents
        if AuthorizationService.is_admin(user):
            return queryset
        
        # Non-admins see only their own documents
        return queryset.filter(owner=user)


class UserManagementService:
    """
    Service for user management operations.
    Only accessible by Admins.
    """
    
    @staticmethod
    def create_user(admin_user: User, username: str, email: str, password: str, 
                   role_name: str, first_name: str = '', last_name: str = '') -> tuple[Optional[User], Optional[str]]:
        """
        Create a new user and assign them a role.
        User must change password on first login.
        
        Args:
            admin_user: The admin creating the user
            username: Username for new user
            email: Email for new user
            password: Temporary password
            role_name: Role to assign (editor or user)
            first_name: Optional first name
            last_name: Optional last name
        
        Returns:
            tuple: (User object, error message) - User is None if error occurred
        """
        # Verify admin has permission
        if not AuthorizationService.can_manage_users(admin_user):
            return None, "Only admins can create users"
        
        # Validate role
        if role_name not in [Role.EDITOR, Role.USER]:
            return None, "Can only create Editor or User roles"
        
        try:
            # Check if username already exists
            if User.objects.filter(username=username).exists():
                return None, "Username already exists"
            
            # Get role
            role = Role.objects.get(name=role_name)
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                force_password_change=True,  # Must change password on first login
                role=role
            )
            
            return user, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def update_user_role(admin_user: User, target_user: User, new_role_name: str) -> tuple[bool, Optional[str]]:
        """
        Update a user's role.
        
        Args:
            admin_user: The admin performing the update
            target_user: The user whose role is being updated
            new_role_name: New role name
        
        Returns:
            tuple: (success bool, error message)
        """
        # Verify admin has permission
        if not AuthorizationService.can_manage_users(admin_user):
            return False, "Only admins can update user roles"
        
        # Cannot change default admin role
        if target_user.is_default_admin:
            return False, "Cannot change default admin role"
        
        # Cannot change your own role
        if admin_user.id == target_user.id:
            return False, "Cannot change your own role"
        
        try:
            # Get new role
            new_role = Role.objects.get(name=new_role_name)
            
            # Update role
            target_user.role = new_role
            target_user.save()
            
            return True, None
            
        except Role.DoesNotExist:
            return False, "Invalid role"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def delete_user(admin_user: User, target_user: User) -> tuple[bool, Optional[str]]:
        """
        Deactivate a user account.
        
        Args:
            admin_user: The admin performing the deletion
            target_user: The user to deactivate
        
        Returns:
            tuple: (success bool, error message)
        """
        # Verify admin has permission
        if not AuthorizationService.can_manage_users(admin_user):
            return False, "Only admins can delete users"
        
        # Cannot delete default admin
        if target_user.is_default_admin:
            return False, "Cannot delete default admin"
        
        # Cannot delete yourself
        if admin_user.id == target_user.id:
            return False, "Cannot delete yourself"
        
        try:
            # Soft delete - deactivate user
            target_user.is_active = False
            target_user.save()
            
            return True, None
            
        except Exception as e:
            return False, str(e)



class DocumentEditService:
    """
    Service for managing document edit requests and approvals.
    Editors submit edit requests, admins approve/reject them.
    """
    
    @staticmethod
    def can_edit_document(user: User, document: Document) -> bool:
        """
        Check if user can edit a document.
        - Admins can edit directly
        - Editors can submit edit requests
        - Users cannot edit
        """
        if not user or not user.role:
            return False
        
        # Admins can edit directly
        if user.role.name == Role.ADMIN:
            return True
        
        # Editors can submit edit requests (not direct edit)
        if user.role.name == Role.EDITOR:
            return False  # Must use edit request
        
        # Users cannot edit at all
        return False
    
    @staticmethod
    def create_edit_request(editor: User, document_id: int, new_title: str, 
                          new_content: str, reason: str = '') -> tuple[Optional[DocumentEditRequest], Optional[str]]:
        """
        Create an edit request for a document.
        Only editors can create edit requests.
        
        Args:
            editor: The editor creating the request
            document_id: ID of document to edit
            new_title: Proposed new title
            new_content: Proposed new content
            reason: Reason for the edit
        
        Returns:
            tuple: (DocumentEditRequest object, error message)
        """
        # Check if user is an editor
        if not editor.role or editor.role.name != Role.EDITOR:
            return None, "Only editors can submit edit requests"
        
        # Check if document exists
        try:
            document = Document.objects.get(id=document_id)
        except Document.DoesNotExist:
            return None, "Document not found"
        
        # Check if editor has read permission
        if not AuthorizationService.has_permission(editor, 'read'):
            return None, "You don't have permission to access this document"
        
        # Create edit request
        try:
            edit_request = DocumentEditRequest.objects.create(
                document=document,
                requested_by=editor,
                new_title=new_title,
                new_content=new_content,
                reason=reason,
                status=DocumentEditRequest.PENDING
            )
            return edit_request, None
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def review_edit_request(admin: User, request_id: int, approve: bool, 
                          review_comment: str = '') -> tuple[bool, Optional[str]]:
        """
        Admin reviews and approves/rejects an edit request.
        If approved, the document is updated.
        
        Args:
            admin: The admin reviewing the request
            request_id: ID of the edit request
            approve: True to approve, False to reject
            review_comment: Optional comment from admin
        
        Returns:
            tuple: (success bool, error message)
        """
        # Check if user is admin
        if not AuthorizationService.is_admin(admin):
            return False, "Only admins can review edit requests"
        
        # Get edit request
        try:
            edit_request = DocumentEditRequest.objects.select_related('document').get(id=request_id)
        except DocumentEditRequest.DoesNotExist:
            return False, "Edit request not found"
        
        # Check if already reviewed
        if edit_request.status != DocumentEditRequest.PENDING:
            return False, f"Edit request already {edit_request.status}"
        
        # Update request status
        try:
            if approve:
                # Apply the changes to the document
                document = edit_request.document
                document.title = edit_request.new_title
                document.content = edit_request.new_content
                document.save()
                
                edit_request.status = DocumentEditRequest.APPROVED
            else:
                edit_request.status = DocumentEditRequest.REJECTED
            
            edit_request.reviewed_by = admin
            edit_request.review_comment = review_comment
            edit_request.reviewed_at = timezone.now()
            edit_request.save()
            
            return True, None
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_pending_requests(admin: User):
        """
        Get all pending edit requests (Admin only).
        """
        if not AuthorizationService.is_admin(admin):
            return DocumentEditRequest.objects.none()
        
        return DocumentEditRequest.objects.filter(
            status=DocumentEditRequest.PENDING
        ).select_related('document', 'requested_by')
    
    @staticmethod
    def get_user_requests(user: User):
        """
        Get edit requests created by the user.
        """
        return DocumentEditRequest.objects.filter(
            requested_by=user
        ).select_related('document', 'reviewed_by')
