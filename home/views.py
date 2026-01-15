from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

from .models import User, Document, DocumentEditRequest
from .serializers import (
    UserSerializer, DocumentSerializer, LoginSerializer,
    ChangePasswordSerializer, CreateUserSerializer,
    UpdateUserRoleSerializer, DocumentEditRequestSerializer,
    CreateEditRequestSerializer, ReviewEditRequestSerializer
)
from .permissions import (
    CanCreateResource, CanReadResource, CanModifyResource,
    IsAdmin, CanManageUsers
)
from .services import AuthorizationService, UserManagementService, DocumentEditService


class AuthViewSet(viewsets.GenericViewSet):
    """
    ViewSet for authentication operations.
    Endpoints: login, logout, change-password, me
    """
    
    def get_permissions(self):
        """
        Set permissions based on action.
        """
        if self.action == 'login':
            return [AllowAny()]
        return [IsAuthenticated()]
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        """
        Login endpoint - returns JWT tokens.
        POST /api/auth/login/
        """
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        
        if user is None:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                {'error': 'Account is disabled'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if user needs to change password
        if user.force_password_change:
            # Generate tokens but inform user they must change password
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': UserSerializer(user).data,
                'force_password_change': True,
                'message': 'You must change your password before using the system'
            })
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data,
            'force_password_change': False
        })
    
    @action(detail=False, methods=['post'])
    def logout(self, request):
        """
        Logout endpoint - blacklist refresh token.
        POST /api/auth/logout/
        """
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            return Response({'message': 'Logged out successfully'})
        except Exception:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """
        Change password endpoint.
        POST /api/auth/change-password/
        """
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        # Verify old password
        if not user.check_password(old_password):
            return Response(
                {'error': 'Old password is incorrect'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Set new password
        user.set_password(new_password)
        user.force_password_change = False
        user.save()
        
        return Response({'message': 'Password changed successfully'})
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get current user info.
        GET /api/auth/me/
        """
        user = request.user
        data = UserSerializer(user).data
        
        # Add role information
        role = AuthorizationService.get_user_role(user)
        data['role'] = role.name if role else None
        
        return Response(data)


class UserManagementViewSet(viewsets.GenericViewSet):
    """
    ViewSet for user management operations (Admin only).
    Endpoints: list, create, update-role, delete
    """
    permission_classes = [IsAuthenticated, CanManageUsers]
    serializer_class = UserSerializer
    
    def list(self, request):
        """
        List all users.
        GET /api/users/
        """
        users = User.objects.filter(is_active=True).select_related('role')
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    
    def create(self, request):
        """
        Create a new user (Admin only).
        POST /api/users/
        """
        serializer = CreateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user, error = UserManagementService.create_user(
            admin_user=request.user,
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password'],
            role_name=serializer.validated_data['role'],
            first_name=serializer.validated_data.get('first_name', ''),
            last_name=serializer.validated_data.get('last_name', '')
        )
        
        if error:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response(
            UserSerializer(user).data,
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=False, methods=['post'])
    def update_role(self, request):
        """
        Update a user's role (Admin only).
        POST /api/users/update-role/
        """
        serializer = UpdateUserRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user_id = serializer.validated_data['user_id']
        new_role = serializer.validated_data['role']
        
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        success, error = UserManagementService.update_user_role(
            admin_user=request.user,
            target_user=target_user,
            new_role_name=new_role
        )
        
        if not success:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response({'message': 'User role updated successfully'})
    
    def destroy(self, request, pk=None):
        """
        Deactivate a user (Admin only).
        DELETE /api/users/{id}/
        """
        try:
            target_user = User.objects.get(id=pk)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        success, error = UserManagementService.delete_user(
            admin_user=request.user,
            target_user=target_user
        )
        
        if not success:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response({'message': 'User deactivated successfully'})


class DocumentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Document CRUD operations.
    Demonstrates RBAC with approval workflow:
    - Admins can create, read, update, delete directly
    - Editors can create, read, and submit edit requests (not direct update)
    - Users can only read
    """
    serializer_class = DocumentSerializer
    
    def get_permissions(self):
        """
        Set permissions based on action.
        """
        if self.action == 'create':
            return [IsAuthenticated(), CanCreateResource()]
        elif self.action in ['list', 'retrieve']:
            return [IsAuthenticated(), CanReadResource()]
        elif self.action in ['update', 'partial_update', 'destroy']:
            return [IsAuthenticated(), CanModifyResource()]  # Admin only
        elif self.action in ['submit_edit_request']:
            return [IsAuthenticated()]
        return [IsAuthenticated()]
    
    def get_queryset(self):
        """
        Filter documents based on user's access rights.
        """
        user = self.request.user
        
        # Use service to filter accessible documents
        queryset = Document.objects.all()
        return AuthorizationService.filter_accessible_documents(user, queryset)
    
    def perform_create(self, serializer):
        """
        Set owner when creating document.
        """
        serializer.save(owner=self.request.user)
    
    def list(self, request):
        """
        List documents accessible to current user.
        GET /api/documents/
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """
        Get a specific document.
        GET /api/documents/{id}/
        """
        try:
            document = self.get_queryset().get(pk=pk)
        except Document.DoesNotExist:
            return Response(
                {'error': 'Document not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = self.get_serializer(document)
        return Response(serializer.data)
    
    def create(self, request):
        """
        Create a new document.
        POST /api/documents/
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def update(self, request, pk=None):
        """
        Update a document (full update) - ADMIN ONLY.
        Editors must use submit_edit_request instead.
        PUT /api/documents/{id}/
        """
        try:
            document = self.get_queryset().get(pk=pk)
        except Document.DoesNotExist:
            return Response(
                {'error': 'Document not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check object-level permission (Admin only)
        self.check_object_permissions(request, document)
        
        serializer = self.get_serializer(document, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    def partial_update(self, request, pk=None):
        """
        Update a document (partial update) - ADMIN ONLY.
        Editors must use submit_edit_request instead.
        PATCH /api/documents/{id}/
        """
        try:
            document = self.get_queryset().get(pk=pk)
        except Document.DoesNotExist:
            return Response(
                {'error': 'Document not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check object-level permission (Admin only)
        self.check_object_permissions(request, document)
        
        serializer = self.get_serializer(document, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    def destroy(self, request, pk=None):
        """
        Delete a document - ADMIN ONLY.
        DELETE /api/documents/{id}/
        """
        try:
            document = self.get_queryset().get(pk=pk)
        except Document.DoesNotExist:
            return Response(
                {'error': 'Document not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check object-level permission (Admin only)
        self.check_object_permissions(request, document)
        
        document.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=False, methods=['post'], url_path='submit-edit-request')
    def submit_edit_request(self, request):
        """
        Submit an edit request for a document (EDITOR ONLY).
        Editors cannot directly edit - they submit requests for admin approval.
        POST /api/documents/submit-edit-request/
        """
        serializer = CreateEditRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        edit_request, error = DocumentEditService.create_edit_request(
            editor=request.user,
            document_id=serializer.validated_data['document_id'],
            new_title=serializer.validated_data['new_title'],
            new_content=serializer.validated_data['new_content'],
            reason=serializer.validated_data.get('reason', '')
        )
        
        if error:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response(
            DocumentEditRequestSerializer(edit_request).data,
            status=status.HTTP_201_CREATED
        )


class DocumentEditRequestViewSet(viewsets.GenericViewSet):
    """
    ViewSet for managing document edit requests.
    - Editors can view their own requests
    - Admins can view all pending requests and approve/reject them
    """
    serializer_class = DocumentEditRequestSerializer
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def my_requests(self, request):
        """
        Get edit requests created by current user.
        GET /api/edit-requests/my-requests/
        """
        requests_qs = DocumentEditService.get_user_requests(request.user)
        serializer = self.get_serializer(requests_qs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated, IsAdmin])
    def pending(self, request):
        """
        Get all pending edit requests (ADMIN ONLY).
        GET /api/edit-requests/pending/
        """
        requests_qs = DocumentEditService.get_pending_requests(request.user)
        serializer = self.get_serializer(requests_qs, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsAdmin])
    def review(self, request, pk=None):
        """
        Review (approve/reject) an edit request (ADMIN ONLY).
        POST /api/edit-requests/{id}/review/
        """
        serializer = ReviewEditRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        success, error = DocumentEditService.review_edit_request(
            admin=request.user,
            request_id=pk,
            approve=serializer.validated_data['approve'],
            review_comment=serializer.validated_data.get('review_comment', '')
        )
        
        if not success:
            return Response(
                {'error': error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        action_text = 'approved' if serializer.validated_data['approve'] else 'rejected'
        return Response({
            'message': f'Edit request {action_text} successfully'
        })
