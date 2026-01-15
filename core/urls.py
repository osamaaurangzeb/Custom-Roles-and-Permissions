"""
URL configuration for Production-Ready RBAC System
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from home.views import AuthViewSet, UserManagementViewSet, DocumentViewSet, DocumentEditRequestViewSet

# DRF Router for ViewSets
router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'users', UserManagementViewSet, basename='users')
router.register(r'documents', DocumentViewSet, basename='documents')
router.register(r'edit-requests', DocumentEditRequestViewSet, basename='edit-requests')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
