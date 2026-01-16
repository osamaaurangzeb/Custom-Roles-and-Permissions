"""
Custom Exception Handler
Prevents sensitive data leakage in error responses
"""
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that:
    1. Logs detailed errors for debugging
    2. Returns sanitized error messages to clients
    3. Prevents stack traces and sensitive info from leaking
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    # Get request info for logging
    request = context.get('request')
    view = context.get('view')
    
    if response is not None:
        # Log the error with details
        logger.error(
            f"API Error - View: {view.__class__.__name__ if view else 'Unknown'}, "
            f"Status: {response.status_code}, "
            f"User: {getattr(request, 'user', 'Anonymous')}, "
            f"Path: {getattr(request, 'path', 'Unknown')}, "
            f"Error: {exc}"
        )
        
        # Sanitize error response in production
        if not settings.DEBUG:
            # Generic error messages for common status codes
            error_messages = {
                400: 'Invalid request',
                401: 'Authentication required',
                403: 'Permission denied',
                404: 'Resource not found',
                405: 'Method not allowed',
                429: 'Too many requests',
                500: 'Internal server error',
            }
            
            status_code = response.status_code
            
            # Don't expose detailed validation errors in production
            if status_code == 400 and hasattr(exc, 'detail'):
                # Keep field-level validation errors but sanitize messages
                if isinstance(exc.detail, dict):
                    sanitized = {}
                    for field, errors in exc.detail.items():
                        if isinstance(errors, list):
                            sanitized[field] = ['Invalid value' if 'password' in field.lower() else str(e) for e in errors]
                        else:
                            sanitized[field] = 'Invalid value' if 'password' in field.lower() else str(errors)
                    response.data = {'errors': sanitized}
                else:
                    response.data = {'error': error_messages.get(status_code, 'Error occurred')}
            elif status_code >= 500:
                # Never expose internal server errors
                response.data = {'error': 'An unexpected error occurred'}
        
        return response
    
    # Handle unhandled exceptions
    logger.exception(
        f"Unhandled Exception - View: {view.__class__.__name__ if view else 'Unknown'}, "
        f"User: {getattr(request, 'user', 'Anonymous')}, "
        f"Path: {getattr(request, 'path', 'Unknown')}"
    )
    
    # Return generic error in production
    if not settings.DEBUG:
        return Response(
            {'error': 'An unexpected error occurred'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    return None
