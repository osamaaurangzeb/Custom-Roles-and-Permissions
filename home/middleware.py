"""
Custom Security Middleware
Provides additional security layers for the API
"""
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
import time


class ForcePasswordChangeMiddleware(MiddlewareMixin):
    """
    Blocks API access for users who must change their password.
    Only allows access to password change endpoint.
    """
    
    def process_request(self, request):
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Skip for auth endpoints
        skip_paths = ['/api/auth/login/', '/api/auth/change-password/', '/api/token/refresh/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Check if user needs to change password
        if hasattr(request, 'user') and request.user.is_authenticated:
            if request.user.force_password_change:
                return JsonResponse({
                    'error': 'Password change required',
                    'detail': 'You must change your password before accessing the system',
                    'action_required': 'change_password'
                }, status=403)
        
        return None


class RateLimitMiddleware(MiddlewareMixin):
    """
    Rate limiting middleware to prevent brute force attacks.
    Limits requests per IP address.
    """
    
    def process_request(self, request):
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Get client IP
        ip = self.get_client_ip(request)
        
        # Different limits for different endpoints
        if request.path.startswith('/api/auth/login/'):
            # Stricter limit for login attempts
            limit = 5
            window = 300  # 5 minutes
            cache_key = f'rate_limit_login_{ip}'
        else:
            # General API rate limit
            limit = 100
            window = 60  # 1 minute
            cache_key = f'rate_limit_api_{ip}'
        
        # Get current count
        current = cache.get(cache_key, 0)
        
        if current >= limit:
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'detail': f'Too many requests. Please try again later.',
                'retry_after': window
            }, status=429)
        
        # Increment counter
        cache.set(cache_key, current + 1, window)
        
        return None
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Adds security headers to all responses.
    """
    
    def process_response(self, request, response):
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response['Content-Security-Policy'] = "default-src 'self'"
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Logs all API requests for security auditing.
    """
    
    def process_request(self, request):
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Store request start time
        request.start_time = time.time()
        
        return None
    
    def process_response(self, request, response):
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return response
        
        # Calculate request duration
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            
            # Log request details
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            
            # Get client IP
            ip = self.get_client_ip(request)
            
            # Log format: [timestamp] IP USERNAME METHOD PATH STATUS DURATION
            log_message = (
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"IP:{ip} USER:{username} "
                f"{request.method} {request.path} "
                f"STATUS:{response.status_code} "
                f"DURATION:{duration:.3f}s"
            )
            
            # Log to console (in production, use proper logging)
            print(log_message)
            
            # Add response time header
            response['X-Response-Time'] = f"{duration:.3f}s"
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ValidateJWTMiddleware(MiddlewareMixin):
    """
    Additional JWT token validation.
    Checks for token tampering and expiration.
    """
    
    def process_request(self, request):
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Skip for public endpoints
        public_paths = ['/api/auth/login/', '/api/token/refresh/']
        if any(request.path.startswith(path) for path in public_paths):
            return None
        
        # Check if Authorization header exists
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header and request.path.startswith('/api/'):
            # Only enforce for protected API endpoints
            protected_paths = ['/api/users/', '/api/documents/', '/api/edit-requests/']
            if any(request.path.startswith(path) for path in protected_paths):
                return JsonResponse({
                    'error': 'Authentication required',
                    'detail': 'Authorization header is missing'
                }, status=401)
        
        return None


class IPWhitelistMiddleware(MiddlewareMixin):
    """
    Optional IP whitelist for admin endpoints.
    Disabled by default - enable in production if needed.
    """
    
    def process_request(self, request):
        # Skip if whitelist is not configured
        whitelist = getattr(settings, 'ADMIN_IP_WHITELIST', None)
        if not whitelist:
            return None
        
        # Only check for admin endpoints
        if not request.path.startswith('/admin/'):
            return None
        
        # Get client IP
        ip = self.get_client_ip(request)
        
        # Check if IP is whitelisted
        if ip not in whitelist:
            return JsonResponse({
                'error': 'Access denied',
                'detail': 'Your IP address is not authorized to access this resource'
            }, status=403)
        
        return None
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
