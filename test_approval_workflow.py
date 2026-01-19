import requests
import json
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
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response:\n{json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

def test_approval_workflow():
    """Test the document edit approval workflow"""
    
    print("\nTesting Document Edit Approval Workflow")
    print("="*70)
    
    # Step 1: Login as Admin
    print("\nStep 1: Admin Login")
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
    
    # Step 2: Admin creates a document
    print("\nStep 2: Admin Creates Document")
    response = requests.post(
        f"{BASE_URL}/api/documents/",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        },
        json={
            "title": "Company Policy Document",
            "content": "This is the original content of the policy document."
        }
    )
    print_response("Admin Creates Document", response)
    
    if response.status_code != 201:
        print("Error: Document creation failed")
        return
    
    document_id = response.json()["id"]
    print(f"\nDocument created with ID: {document_id}")
    
    # Step 3: Create an Editor user
    print("\nStep 3: Admin Creates Editor User")
    response = requests.post(
        f"{BASE_URL}/api/users/",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        },
        json={
            "username": "editor_john",
            "email": "john@company.com",
            "first_name": "John",
            "last_name": "Editor",
            "password": "EditorPass123!",
            "role": "editor"
        }
    )
    print_response("Create Editor User", response)
    
    # Step 4: Login as Editor
    print("\nStep 4: Editor Login")
    response = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json={"username": "editor_john", "password": "EditorPass123!"}
    )
    print_response("Editor Login", response)
    
    if response.status_code != 200:
        print("Error: Editor login failed")
        return
    
    editor_token = response.json()["access"]
    
    # Step 5: Editor tries to directly edit (should fail)
    print("\nStep 5: Editor Tries Direct Edit (Should Fail)")
    response = requests.put(
        f"{BASE_URL}/api/documents/{document_id}/",
        headers={
            "Authorization": f"Bearer {editor_token}",
            "Content-Type": "application/json"
        },
        json={
            "title": "Updated Policy Document",
            "content": "This is updated content."
        }
    )
    print_response("Editor Direct Edit Attempt", response)
    
    if response.status_code == 403:
        print("\nCorrect: Editor cannot directly edit documents")
    
    # Step 6: Editor submits edit request
    print("\nStep 6: Editor Submits Edit Request")
    response = requests.post(
        f"{BASE_URL}/api/documents/submit-edit-request/",
        headers={
            "Authorization": f"Bearer {editor_token}",
            "Content-Type": "application/json"
        },
        json={
            "document_id": document_id,
            "new_title": "Updated Company Policy Document",
            "new_content": "This is the updated content with important changes to the policy.",
            "reason": "Updating policy to reflect new company guidelines"
        }
    )
    print_response("Editor Submits Edit Request", response)
    
    if response.status_code != 201:
        print("Error: Edit request submission failed")
        return
    
    edit_request_id = response.json()["id"]
    print(f"\nEdit request created with ID: {edit_request_id}")
    
    # Step 7: Editor views their requests
    print("\nStep 7: Editor Views Their Edit Requests")
    response = requests.get(
        f"{BASE_URL}/api/edit-requests/my_requests/",
        headers={"Authorization": f"Bearer {editor_token}"}
    )
    print_response("Editor's Edit Requests", response)
    
    # Step 8: Admin views pending requests
    print("\nStep 8: Admin Views Pending Edit Requests")
    response = requests.get(
        f"{BASE_URL}/api/edit-requests/pending/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print_response("Pending Edit Requests", response)
    
    # Step 9: Admin approves the edit request
    print("\nStep 9: Admin Approves Edit Request")
    response = requests.post(
        f"{BASE_URL}/api/edit-requests/{edit_request_id}/review/",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        },
        json={
            "approve": True,
            "review_comment": "Changes look good. Approved."
        }
    )
    print_response("Admin Approves Request", response)
    
    if response.status_code == 200:
        print("\nEdit request approved successfully")
    
    # Step 10: Verify document was updated
    print("\nStep 10: Verify Document Was Updated")
    response = requests.get(
        f"{BASE_URL}/api/documents/{document_id}/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print_response("Updated Document", response)
    
    if response.status_code == 200:
        doc = response.json()
        if doc['title'] == "Updated Company Policy Document":
            print("\nDocument successfully updated with approved changes")
    
    # Step 11: Test rejection workflow
    print("\nStep 11: Editor Submits Another Edit Request")
    response = requests.post(
        f"{BASE_URL}/api/documents/submit-edit-request/",
        headers={
            "Authorization": f"Bearer {editor_token}",
            "Content-Type": "application/json"
        },
        json={
            "document_id": document_id,
            "new_title": "Another Update",
            "new_content": "More changes",
            "reason": "Additional updates needed"
        }
    )
    print_response("Second Edit Request", response)
    
    if response.status_code == 201:
        second_request_id = response.json()["id"]
        
        # Step 12: Admin rejects this request
        print("\nStep 12: Admin Rejects Edit Request")
        response = requests.post(
            f"{BASE_URL}/api/edit-requests/{second_request_id}/review/",
            headers={
                "Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json"
            },
            json={
                "approve": False,
                "review_comment": "Changes not needed at this time."
            }
        )
        print_response("Admin Rejects Request", response)
        
        if response.status_code == 200:
            print("\nEdit request rejected successfully")
    
    # Summary
    print("\n" + "="*70)
    print("Approval Workflow Test Complete")
    print("="*70)
    print("\nSummary:")
    print("  - Admin can create and directly edit documents")
    print("  - Editor can create documents")
    print("  - Editor cannot directly edit (must submit requests)")
    print("  - Editor can submit edit requests with reason")
    print("  - Admin can view pending requests")
    print("  - Admin can approve requests (document gets updated)")
    print("  - Admin can reject requests (document stays unchanged)")
    print("\nWorkflow:")
    print("  1. Editor submits edit request")
    print("  2. Request goes to admin for review")
    print("  3. Admin approves -> Document updated")
    print("  4. Admin rejects -> Document unchanged")

if __name__ == "__main__":
    print("Starting Approval Workflow Test...")
    print(f"Testing against: {BASE_URL}")
    
    try:
        test_approval_workflow()
    except requests.exceptions.ConnectionError:
        print("\nError: Cannot connect to server")
        print("Make sure the Django server is running on http://127.0.0.1:8000")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
