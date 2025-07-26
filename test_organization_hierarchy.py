#!/usr/bin/env python3
"""
CertGuard AI Organization Hierarchy Testing
Focus on testing the new hierarchical organization system
"""

import requests
import json
from datetime import datetime

class OrganizationHierarchyTester:
    def __init__(self):
        self.base_url = "http://localhost:8001"
        self.api_url = f"{self.base_url}/api"
        self.superadmin_token = None
        self.admin_token = None
        self.org_id = None
        self.admin_id = None
        self.user_id = None
        
    def make_request(self, method, endpoint, data=None, token=None):
        """Make HTTP request"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        headers = {'Content-Type': 'application/json'}
        
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            else:
                return False, {"error": f"Unsupported method: {method}"}
            
            return response.status_code, response.json() if response.text else {}
            
        except Exception as e:
            return 0, {"error": str(e)}
    
    def test_superadmin_login(self):
        """Test Super Admin login"""
        print("1. Testing Super Admin Login...")
        
        login_data = {
            "username": "superadmin",
            "password": "CertGuard@2025!"
        }
        
        status, response = self.make_request('POST', '/auth/login', login_data)
        
        if status == 200 and 'access_token' in response:
            self.superadmin_token = response['access_token']
            print(f"   ✅ Super Admin login successful: {response['user']['username']} ({response['user']['role']})")
            return True
        else:
            print(f"   ❌ Super Admin login failed: {response}")
            return False
    
    def test_create_organization(self):
        """Test organization creation or use existing"""
        print("2. Testing Organization Creation...")
        
        # First try to get existing organizations
        status, orgs = self.make_request('GET', '/organizations', token=self.superadmin_token)
        
        if status == 200 and isinstance(orgs, list) and len(orgs) > 0:
            # Use existing organization
            self.org_id = orgs[0]['id']
            print(f"   ✅ Using existing organization: {orgs[0]['name']} (ID: {self.org_id[:8]}...)")
            return True
        
        # If no organizations exist, create one
        org_data = {
            "name": f"Test Organization {datetime.now().strftime('%H%M%S')}",
            "description": "Test organization for hierarchy testing",
            "cnpj": "12.345.678/0001-90",
            "address": "Test Address",
            "phone": "(11) 3456-7890",
            "email": "test@testorg.com.br"
        }
        
        status, response = self.make_request('POST', '/organizations', org_data, self.superadmin_token)
        
        if status == 200 and 'id' in response:
            self.org_id = response['id']
            print(f"   ✅ Organization created: {response['name']} (ID: {self.org_id[:8]}...)")
            return True
        else:
            print(f"   ❌ Organization creation failed: {response}")
            return False
    
    def test_get_organizations(self):
        """Test getting organizations"""
        print("3. Testing Get Organizations...")
        
        status, response = self.make_request('GET', '/organizations', token=self.superadmin_token)
        
        if status == 200 and isinstance(response, list):
            print(f"   ✅ Retrieved {len(response)} organizations")
            for org in response:
                print(f"      - {org['name']} (ID: {org['id'][:8]}...)")
            return True
        else:
            print(f"   ❌ Get organizations failed: {response}")
            return False
    
    def test_create_admin(self):
        """Test creating admin for organization"""
        print("4. Testing Admin Creation for Organization...")
        
        if not self.org_id:
            print("   ❌ No organization ID available")
            return False
        
        admin_data = {
            "username": f"admin_test_{datetime.now().strftime('%H%M%S')}",
            "email": f"admin.test.{datetime.now().strftime('%H%M%S')}@testorg.com.br",
            "full_name": "Test Administrator",
            "password": "AdminPass123!",
            "role": "admin",
            "organization_id": self.org_id
        }
        
        status, response = self.make_request('POST', '/users', admin_data, self.superadmin_token)
        
        if status == 200 and 'id' in response:
            self.admin_id = response['id']
            print(f"   ✅ Admin created: {response['username']} for org: {response.get('organization_id', 'None')[:8]}...")
            return True
        else:
            print(f"   ❌ Admin creation failed: Status {status}, Response: {response}")
            return False
    
    def test_admin_login(self):
        """Test admin login"""
        print("5. Testing Admin Login...")
        
        # Get admin username
        status, users = self.make_request('GET', '/users', token=self.superadmin_token)
        admin_username = None
        
        if status == 200:
            for user in users:
                if user.get('id') == self.admin_id:
                    admin_username = user.get('username')
                    break
        
        if not admin_username:
            print("   ❌ Could not find admin username")
            return False
        
        login_data = {
            "username": admin_username,
            "password": "AdminPass123!"
        }
        
        status, response = self.make_request('POST', '/auth/login', login_data)
        
        if status == 200 and 'access_token' in response:
            self.admin_token = response['access_token']
            print(f"   ✅ Admin login successful: {response['user']['username']} ({response['user']['role']})")
            return True
        else:
            print(f"   ❌ Admin login failed: {response}")
            return False
    
    def test_admin_create_user(self):
        """Test admin creating user in their organization"""
        print("6. Testing Admin Creating User in Organization...")
        
        user_data = {
            "username": f"user_advocacia_{datetime.now().strftime('%H%M%S')}",
            "email": "usuario@advocaciadigital.com.br",
            "full_name": "Usuário Advocacia Digital",
            "password": "UserPass123!",
            "role": "user"
        }
        
        status, response = self.make_request('POST', '/users', user_data, self.admin_token)
        
        if status == 200 and 'id' in response:
            self.user_id = response['id']
            print(f"   ✅ User created by admin: {response['username']} in org: {response['organization_id'][:8]}...")
            return True
        else:
            print(f"   ❌ User creation by admin failed: {response}")
            return False
    
    def test_admin_view_users(self):
        """Test admin viewing users in their organization"""
        print("7. Testing Admin Viewing Organization Users...")
        
        status, response = self.make_request('GET', '/users', token=self.admin_token)
        
        if status == 200 and isinstance(response, list):
            org_users = [u for u in response if u.get('organization_id') == self.org_id]
            print(f"   ✅ Admin sees {len(response)} total users, {len(org_users)} from their organization")
            return True
        else:
            print(f"   ❌ Admin view users failed: {response}")
            return False
    
    def test_hierarchy_validation(self):
        """Test hierarchy validation rules"""
        print("8. Testing Hierarchy Validation Rules...")
        
        # Test 1: Admin without organization should fail
        admin_no_org = {
            "username": f"admin_no_org_{datetime.now().strftime('%H%M%S')}",
            "email": "admin.noorg@test.com",
            "full_name": "Admin Without Organization",
            "password": "AdminPass123!",
            "role": "admin"
        }
        
        status1, response1 = self.make_request('POST', '/users', admin_no_org, self.superadmin_token)
        test1_passed = status1 == 400 and 'organization' in str(response1.get('detail', '')).lower()
        
        # Test 2: Admin creating another admin should fail
        admin_by_admin = {
            "username": f"admin_by_admin_{datetime.now().strftime('%H%M%S')}",
            "email": "admin.byadmin@test.com",
            "full_name": "Admin Created by Admin",
            "password": "AdminPass123!",
            "role": "admin"
        }
        
        status2, response2 = self.make_request('POST', '/users', admin_by_admin, self.admin_token)
        test2_passed = status2 == 403 and 'admin can only create user' in str(response2.get('detail', '')).lower()
        
        print(f"   {'✅' if test1_passed else '❌'} Admin without org validation: {'BLOCKED' if test1_passed else 'ALLOWED'}")
        print(f"   {'✅' if test2_passed else '❌'} Admin creating admin validation: {'BLOCKED' if test2_passed else 'ALLOWED'}")
        
        return test1_passed and test2_passed
    
    def run_all_tests(self):
        """Run all organization hierarchy tests"""
        print("🏢 CertGuard AI - Organization Hierarchy System Tests")
        print("=" * 60)
        
        tests = [
            self.test_superadmin_login,
            self.test_create_organization,
            self.test_get_organizations,
            self.test_create_admin,
            self.test_admin_login,
            self.test_admin_create_user,
            self.test_admin_view_users,
            self.test_hierarchy_validation
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
                print()
            except Exception as e:
                print(f"   ❌ Test failed with exception: {e}")
                print()
        
        print("=" * 60)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All organization hierarchy tests passed!")
            return 0
        else:
            print(f"⚠️  {total - passed} tests failed.")
            return 1

if __name__ == "__main__":
    tester = OrganizationHierarchyTester()
    exit(tester.run_all_tests())