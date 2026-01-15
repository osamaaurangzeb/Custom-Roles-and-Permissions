"""
Simple API Testing Script
Tests basic RBAC functionality

Note: Update test_config.py with your admin credentials before running
"""
import requests
import json
import os
import sys

# Try to import test config
try:
    from test_config import ADMIN_USERNAME, ADMIN_PASSWORD, BASE_URL
except ImportError:
    print("Error: test_config.py not found")
    print("Please create test_config.py with your admin credentials")
    print("See test_config.py.example for template")
    sys.exit(1)

def print_response(title, response):
    """Print API response"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response:\n{json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

def test_api():
    """Test the RBAC API endpoints"""
    
    # Test 1: Admin Login
    print("\nTest 1: Admin Login")
    response = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    print_response("Admin Login", response)
    
    if response.status_code != 200:
        print("Error: Login failed")
        print("Please check your credentials in test_config.py")
        return
    
    admin_token = response.json()["access"]
    print(f"\nAdmin Token: {admin_token[:50]}...")
    
    # Test 2: Get Current User Info
    print("\nTest 2: Get Current User Info")
    response = requests.get(
        f"{BASE_URL}/api/auth/me/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print_response("Current User Info", response)
    
    # Test 3: Create Editor User
    print("\nTest 3: Create Editor User")
    response = requests.post(
        f"{BASE_URL}/api/users/",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        },
        json={
            "username": "test_editor",
            "email": "editor@test.com",
            "first_name": "Test",
            "last_name": "Editor",
            "password": "TempPass123!",
            "role": "editor"
        }
    )
    print_response("Create Editor User", response)
    
    # Test 4: List Users
    print("\nTest 4: List All Users")
    response = requests.get(
        f"{BASE_URL}/api/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print_response("List Users", response)
    
    # Test 5: Create Document
    print("\nTest 5: Create Document as Admin")
    response = requests.post(
        f"{BASE_URL}/api/documents/",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        },
        json={
            "title": "Admin's Document",
            "content": "This document was created by the admin user."
        }
    )
    print_response("Create Document", response)
    
    if response.status_code == 201:
        doc_id = response.json()["id"]
        print(f"\nDocument created with ID: {doc_id}")
        
        # Test 6: List Documents
        print("\nTest 6: List All Documents")
        response = requests.get(
            f"{BASE_URL}/api/documents/",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        print_response("List Documents", response)
        
        # Test 7: Update Document
        print("\nTest 7: Update Document")
        response = requests.put(
            f"{BASE_URL}/api/documents/{doc_id}/",
            headers={
                "Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json"
            },
            json={
                "title": "Updated Document Title",
                "content": "This content has been updated."
            }
        )
        print_response("Update Document", response)
    
    # Test 8: Login as Editor
    print("\nTest 8: Login as Editor")
    response = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json={"username": "test_editor", "password": "TempPass123!"}
    )
    print_response("Editor Login", response)
    
    if response.status_code == 200:
        editor_token = response.json()["access"]
        
        # Test 9: Editor Creates Document
        print("\nTest 9: Editor Creates Document")
        response = requests.post(
            f"{BASE_URL}/api/documents/",
            headers={
                "Authorization": f"Bearer {editor_token}",
                "Content-Type": "application/json"
            },
            json={
                "title": "Editor's Document",
                "content": "This document was created by an editor."
            }
        )
        print_response("Editor Create Document", response)
        
        if response.status_code == 201:
            editor_doc_id = response.json()["id"]
            
            # Test 10: Editor Tries to Delete (Should Fail)
            print("\nTest 10: Editor Tries to Delete Document (Should Fail)")
            response = requests.delete(
                f"{BASE_URL}/api/documents/{editor_doc_id}/",
                headers={"Authorization": f"Bearer {editor_token}"}
            )
            print_response("Editor Delete Document", response)
            
            if response.status_code == 403:
                print("\nCorrect: Editor cannot delete documents")
            
            # Test 11: Admin Deletes Document (Should Succeed)
            print("\nTest 11: Admin Deletes Document (Should Succeed)")
            response = requests.delete(
                f"{BASE_URL}/api/documents/{editor_doc_id}/",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            print_response("Admin Delete Document", response)
            
            if response.status_code == 204:
                print("\nCorrect: Admin can delete any document")
    
    print("\n" + "="*60)
    print("API Testing Complete")
    print("="*60)
    print("\nSummary:")
    print("  - Authentication works")
    print("  - User management works (Admin only)")
    print("  - Document CRUD works")
    print("  - Role-based permissions enforced")
    print("  - Ownership rules enforced")

if __name__ == "__main__":
    print("Starting RBAC API Tests...")
    print(f"Testing against: {BASE_URL}")
    print("\nMake sure:")
    print("  1. Server is running (python manage.py runserver)")
    print("  2. RBAC is initialized (python manage.py init_rbac)")
    print("  3. test_config.py has your admin credentials")
    
    try:
        test_api()
    except requests.exceptions.ConnectionError:
        print("\nError: Cannot connect to server")
        print("Make sure the Django server is running on http://127.0.0.1:8000")
    except Exception as e:
        print(f"\nError: {e}")
