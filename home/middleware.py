from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
import time
import logging
import ipaddress

logger = logging.getLogger(__name__)


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
                # Log blocked access attempt for auditing
                logger.warning(
                    f"Blocked access for user {request.user.username} - password change required. "
                    f"Path: {request.path}, IP: {self.get_client_ip(request)}"
                )
                
                response = JsonResponse({
                    'error': 'Password change required',
                    'detail': 'You must change your password before accessing the system',
                    'action_required': 'change_password'
                }, status=403)
                
                # Add custom header for API clients
                response['X-Password-Change-Required'] = 'true'
                return response
        
        return None
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RateLimitMiddleware(MiddlewareMixin):
    """
    Rate limiting middleware to prevent brute force attacks.
    Uses cache.incr() to avoid race conditions.
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
        
        # Use cache.incr() to avoid race conditions
        try:
            current = cache.incr(cache_key)
        except ValueError:
            # Key doesn't exist, create it
            cache.set(cache_key, 1, window)
            current = 1
        
        if current > limit:
            # Calculate retry_after based on TTL
            retry_after = cache.ttl(cache_key) if hasattr(cache, 'ttl') else window
            
            logger.warning(
                f"Rate limit exceeded for IP {ip} on {request.path}. "
                f"Count: {current}/{limit}"
            )
            
            response = JsonResponse({
                'error': 'Rate limit exceeded',
                'detail': f'Too many requests. Please try again later.',
                'retry_after': retry_after
            }, status=429)
            
            response['Retry-After'] = str(retry_after)
            return response
        
        return None
    
    def get_client_ip(self, request):
        """Get client IP address from request, handling proxies"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the first IP in the chain (original client)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Adds security headers to all responses.
    Note: Adjust CSP policy based on your frontend requirements.
    """
    
    def process_response(self, request, response):
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # CSP: Adjust based on your needs (CDNs, fonts, etc.)
        # For API-only, 'self' is fine. For frontend, you may need to add domains.
        csp_policy = getattr(settings, 'CONTENT_SECURITY_POLICY', "default-src 'self'")
        response['Content-Security-Policy'] = csp_policy
        
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Logs all API requests for security auditing.
    Uses Python logging module for production-ready logging.
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
            
            # Get request details
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            ip = self.get_client_ip(request)
            
            # Log using Python logging module
            logger.info(
                f"API Request - IP:{ip} USER:{username} "
                f"{request.method} {request.path} "
                f"STATUS:{response.status_code} "
                f"DURATION:{duration:.3f}s"
            )
            
            # Add response time header
            response['X-Response-Time'] = f"{duration:.3f}s"
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ValidateJWTMiddleware(MiddlewareMixin):
    """
    Additional JWT token validation.
    Validates token signature and expiration using DRF's JWT authentication.
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
        
        # Only enforce for protected API endpoints
        protected_paths = ['/api/users/', '/api/documents/', '/api/edit-requests/']
        if any(request.path.startswith(path) for path in protected_paths):
            if not auth_header:
                return JsonResponse({
                    'error': 'Authentication required',
                    'detail': 'Authorization header is missing'
                }, status=401)
            
            # Validate JWT token signature and expiration
            if auth_header.startswith('Bearer '):
                try:
                    jwt_auth = JWTAuthentication()
                    validated_token = jwt_auth.get_validated_token(auth_header.split(' ')[1])
                    # Token is valid, continue
                except (InvalidToken, TokenError) as e:
                    logger.warning(f"Invalid JWT token from IP {self.get_client_ip(request)}: {str(e)}")
                    return JsonResponse({
                        'error': 'Invalid token',
                        'detail': str(e)
                    }, status=401)
        
        return None
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class IPWhitelistMiddleware(MiddlewareMixin):
    """
    Optional IP whitelist for admin endpoints.
    Supports CIDR notation for IP ranges.
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
        
        # Check if IP is whitelisted (supports CIDR notation)
        if not self.is_ip_allowed(ip, whitelist):
            logger.warning(f"Blocked admin access from unauthorized IP: {ip}")
            return JsonResponse({
                'error': 'Access denied',
                'detail': 'Your IP address is not authorized to access this resource'
            }, status=403)
        
        return None
    
    def is_ip_allowed(self, ip, whitelist):
        """Check if IP is in whitelist, supporting CIDR notation"""
        try:
            client_ip = ipaddress.ip_address(ip)
            for allowed in whitelist:
                try:
                    # Check if it's a network (CIDR notation)
                    if '/' in allowed:
                        if client_ip in ipaddress.ip_network(allowed, strict=False):
                            return True
                    # Check exact IP match
                    elif client_ip == ipaddress.ip_address(allowed):
                        return True
                except ValueError:
                    # Invalid IP format in whitelist, skip
                    continue
            return False
        except ValueError:
            # Invalid client IP format
            return False
    
    def get_client_ip(self, request):
        """Get client IP address from request, handling proxies carefully"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the first IP in the chain (original client)
            # In production with trusted proxies, you might want the last trusted IP
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
