"""
Test Security Middleware
Verifies that all security middleware is working correctly
"""
import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def test_security_headers():
    """Test that security headers are present"""
    print("\nTest 1: Security Headers")
    print("="*60)
    
    response = requests.get(f"{BASE_URL}/api/auth/login/")
    
    headers_to_check = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    print("Checking security headers...")
    for header in headers_to_check:
        if header in response.headers:
            print(f"  ✓ {header}: {response.headers[header]}")
        else:
            print(f"  ✗ {header}: Missing")
    
    return all(header in response.headers for header in headers_to_check)


def test_rate_limiting():
    """Test rate limiting on login endpoint"""
    print("\nTest 2: Rate Limiting")
    print("="*60)
    
    print("Attempting 6 login requests (limit is 5)...")
    
    for i in range(6):
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={"username": "test", "password": "wrong"}
        )
        print(f"  Attempt {i+1}: Status {response.status_code}")
        
        if response.status_code == 429:
            print("  ✓ Rate limit enforced after 5 attempts")
            return True
        
        time.sleep(0.1)
    
    print("  ✗ Rate limit not enforced")
    return False


def test_jwt_validation():
    """Test JWT validation middleware"""
    print("\nTest 3: JWT Validation")
    print("="*60)
    
    # Try to access protected endpoint without token
    response = requests.get(f"{BASE_URL}/api/documents/")
    
    if response.status_code == 401:
        print(f"  ✓ Protected endpoint requires authentication")
        print(f"  Response: {response.json()}")
        return True
    else:
        print(f"  ✗ Protected endpoint accessible without token")
        return False


def test_request_logging():
    """Test that requests are being logged"""
    print("\nTest 4: Request Logging")
    print("="*60)
    
    response = requests.get(f"{BASE_URL}/api/auth/login/")
    
    if 'X-Response-Time' in response.headers:
        print(f"  ✓ Request logging active")
        print(f"  Response time: {response.headers['X-Response-Time']}")
        return True
    else:
        print(f"  ✗ Request logging not active")
        return False


def main():
    print("Testing Security Middleware")
    print("="*60)
    
    results = {
        'Security Headers': test_security_headers(),
        'Rate Limiting': test_rate_limiting(),
        'JWT Validation': test_jwt_validation(),
        'Request Logging': test_request_logging()
    }
    
    print("\n" + "="*60)
    print("Test Results Summary")
    print("="*60)
    
    for test_name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        symbol = "✓" if passed else "✗"
        print(f"  {symbol} {test_name}: {status}")
    
    all_passed = all(results.values())
    
    print("\n" + "="*60)
    if all_passed:
        print("All security middleware tests passed!")
    else:
        print("Some security middleware tests failed!")
    print("="*60)


if __name__ == "__main__":
    print("Starting Security Middleware Tests...")
    print(f"Testing against: {BASE_URL}\n")
    
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\nError: Cannot connect to server")
        print("Make sure the Django server is running on http://127.0.0.1:8000")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
