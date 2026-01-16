# Role-Based Access Control System with Approval Workflow

A Django REST Framework application implementing role-based access control with a document edit approval workflow.

## Features

- Role-based permissions (Admin, Editor, User)
- JWT authentication
- Document edit approval workflow
- Editors submit edit requests that require admin approval
- Users have read-only access
- Database-driven permissions

## Quick Start

### Installation

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Setup database
python manage.py makemigrations
python manage.py migrate
python manage.py init_rbac
```

### Start Server

```bash
python manage.py runserver
```

Server runs at: http://127.0.0.1:8000

### Admin Setup

During `init_rbac`, you'll be prompted to create an admin account with:
- Custom username
- Email address
- Secure password (validated by Django)

## Role Permissions

| Role   | Create | Read | Direct Edit | Submit Edit Request | Approve/Reject |
|--------|--------|------|-------------|---------------------|----------------|
| Admin  | Yes    | Yes  | Yes         | N/A                 | Yes            |
| Editor | Yes    | Yes  | No          | Yes                 | No             |
| User   | No     | Yes  | No          | No                  | No             |

## Approval Workflow

1. Editor creates or wants to edit a document
2. Editor submits edit request with proposed changes and reason
3. Request goes to admin with status "pending"
4. Admin reviews the request
5. Admin approves: Document is updated with new content
6. Admin rejects: Document remains unchanged

## API Endpoints

### Authentication

- POST /api/auth/login/ - Login and get JWT tokens
- POST /api/auth/logout/ - Logout
- POST /api/auth/change-password/ - Change password
- GET /api/auth/me/ - Get current user info
- POST /api/token/refresh/ - Refresh access token

### User Management (Admin Only)

- GET /api/users/ - List all users
- POST /api/users/ - Create new user
- POST /api/users/update-role/ - Update user role
- DELETE /api/users/{id}/ - Deactivate user

### Documents

- GET /api/documents/ - List documents
- POST /api/documents/ - Create document
- GET /api/documents/{id}/ - Get specific document
- PUT /api/documents/{id}/ - Update document (Admin only)
- DELETE /api/documents/{id}/ - Delete document (Admin only)

### Edit Requests

- POST /api/documents/submit-edit-request/ - Submit edit request (Editor only)
- GET /api/edit-requests/my_requests/ - View your edit requests
- GET /api/edit-requests/pending/ - View pending requests (Admin only)
- POST /api/edit-requests/{id}/review/ - Approve or reject request (Admin only)

## Example Usage

### Login

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Admin@12345"}'
```

### Create User

```bash
curl -X POST http://127.0.0.1:8000/api/users/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "username": "john_editor",
    "email": "john@example.com",
    "password": "TempPass123!",
    "role": "editor"
  }'
```

### Submit Edit Request

```bash
curl -X POST http://127.0.0.1:8000/api/documents/submit-edit-request/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer EDITOR_TOKEN" \
  -d '{
    "document_id": 1,
    "new_title": "Updated Title",
    "new_content": "Updated content",
    "reason": "Fixing typos and updating information"
  }'
```

### Approve Edit Request

```bash
curl -X POST http://127.0.0.1:8000/api/edit-requests/1/review/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -d '{
    "approve": true,
    "review_comment": "Changes look good"
  }'
```

## Testing

### Setup Test Configuration

1. Copy the test configuration template:
```bash
cp test_config.py.example test_config.py
```

2. Edit `test_config.py` and add your admin credentials

3. Run the test scripts:
```bash
# Test basic RBAC functionality
python test_api_simple.py

# Test approval workflow
python test_approval_workflow.py

# Test security middleware
python test_security_middleware.py
```

Note: `test_config.py` is in `.gitignore` to prevent committing credentials

### Security Middleware Tests

The security test verifies:
- Security headers are present in responses
- Rate limiting prevents brute force attacks
- JWT validation protects endpoints
- Request logging tracks all API calls

See `SECURITY.md` for detailed security configuration.

```bash
python test_api_simple.py
python test_approval_workflow.py
```

## Project Structure

```
├── core/                   # Django project settings
│   ├── settings.py
│   └── urls.py
├── home/                   # Main application
│   ├── models.py          # Database models
│   ├── serializers.py     # API serializers
│   ├── views.py           # API views
│   ├── permissions.py     # Permission classes
│   ├── services.py        # Business logic
│   ├── middleware.py      # Custom middleware
│   └── management/
│       └── commands/
│           └── init_rbac.py
├── manage.py
└── requirements.txt
```

## Technology Stack

- Django 5.2.10
- Django REST Framework 3.16.1
- JWT Authentication (djangorestframework-simplejwt 5.5.1)
- SQLite (development) / PostgreSQL (production)
- Python 3.11+

## Security Features

### Authentication & Authorization
- JWT token-based authentication
- Password hashing with Django's built-in system
- Password validation (minimum length, complexity requirements)
- No hardcoded credentials
- Token refresh mechanism
- Token blacklisting on logout
- Permission-based access control
- Ownership validation
- Audit trail for edit requests

### Custom Security Middleware
1. **ForcePasswordChangeMiddleware** - Enforces password change for new users
   - Logs blocked access attempts for auditing
   - Adds X-Password-Change-Required header for API clients
2. **RateLimitMiddleware** - Prevents brute force attacks
   - Login attempts: 5 per 5 minutes per IP
   - API requests: 100 per minute per IP
   - Uses cache.incr() to prevent race conditions
   - Adds Retry-After header in responses
3. **SecurityHeadersMiddleware** - Adds security headers to all responses
   - X-Content-Type-Options
   - X-Frame-Options
   - X-XSS-Protection
   - Strict-Transport-Security
   - Content-Security-Policy (configurable in settings)
   - Referrer-Policy
   - Permissions-Policy
4. **RequestLoggingMiddleware** - Logs all API requests for auditing
   - Uses Python logging module (production-ready)
   - Logs to console and file (logs/security.log)
   - Tracks IP, user, method, path, status, duration
5. **ValidateJWTMiddleware** - Additional JWT token validation
   - Validates token signature and expiration
   - Integrates with DRF's JWT authentication
   - Logs invalid token attempts
6. **IPWhitelistMiddleware** - Optional IP whitelist for admin access
   - Supports CIDR notation for IP ranges (e.g., 192.168.1.0/24)
   - Disabled by default
   - Handles proxy headers correctly

### Production Considerations
- Rate limiting uses Django cache - use Redis or Memcached for multi-server deployments
- Logging writes to logs/security.log - configure log rotation in production
- CSP policy is configurable via CONTENT_SECURITY_POLICY setting
- IP whitelist supports both exact IPs and CIDR ranges

## Security Audit Checklist

The following security measures are implemented:

### Authentication & Authorization
- JWT token-based authentication with short-lived tokens (30 min access, 1 day refresh)
- Token blacklisting enabled for logout
- Account lockout after 5 failed login attempts (15 min lockout)
- Password validation using Django validators (min 10 chars, complexity requirements)
- Force password change for new users
- No hardcoded credentials

### Input Validation & Sanitization
- All user inputs are sanitized using Django's escape() to prevent XSS
- Input length limits on all fields
- Username format validation (alphanumeric + @/./+/-/_)
- Email uniqueness validation
- Integer ID validation with min_value constraints

### Error Handling
- Custom exception handler prevents sensitive data leakage
- Generic error messages in production
- Detailed logging for debugging (server-side only)
- Stack traces hidden in production

### Security Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HSTS)
- Content-Security-Policy
- Referrer-Policy
- Permissions-Policy

### Production Settings (auto-enabled when DEBUG=False)
- HTTPS redirect
- Secure cookies (HttpOnly, Secure, SameSite)
- HSTS with preload
- Request body size limits (5MB)


## License

This project is licensed under the MIT License.
