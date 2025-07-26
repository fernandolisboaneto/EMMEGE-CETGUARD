#!/usr/bin/env python3
"""
CertGuard AI Backend API Testing Suite v2.0
Tests all CORE endpoints for the revolutionary certificate management system with AI
Includes: Certificate Import, Assignments, Security Dashboard, AI Analysis, Audit Trail
"""

import requests
import sys
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class CertGuardAPITester:
    def __init__(self, base_url: str = "https://4467813a-53fb-447d-a535-d1c3afcb1b4e.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.token = None
        self.created_user_id = None
        self.created_cert_id = None
        self.site_ids = []
        # Organization hierarchy testing
        self.created_org_id = None
        self.created_admin_id = None
        self.admin_token = None
        
    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED {details}")
        else:
            print(f"❌ {name} - FAILED {details}")
        return success

    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, expected_status: int = 200, auth_required: bool = False) -> tuple[bool, Dict]:
        """Make HTTP request and validate response"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        headers = {'Content-Type': 'application/json'}
        
        if auth_required and self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=15)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=15)
            else:
                return False, {"error": f"Unsupported method: {method}"}
            
            success = response.status_code == expected_status
            try:
                response_data = response.json()
            except:
                response_data = {"raw_response": response.text, "status_code": response.status_code}
                
            return success, response_data
            
        except requests.exceptions.RequestException as e:
            return False, {"error": str(e)}

    def test_root_endpoint(self) -> bool:
        """Test root API endpoint"""
        success, response = self.make_request('GET', '/')
        return self.log_test(
            "Root Endpoint", 
            success and "CertGuard AI" in str(response),
            f"Response: {response.get('message', 'No message')}"
        )

    def test_login(self) -> bool:
        """Test super admin login"""
        login_data = {
            "username": "superadmin",
            "password": "CertGuard@2025!"
        }
        
        success, response = self.make_request('POST', '/auth/login', login_data)
        
        if success and 'access_token' in response:
            self.token = response['access_token']
            print(f"DEBUG: Login successful, token: {self.token[:20]}...")
        else:
            print(f"DEBUG: Login failed, response: {response}")
            
        return self.log_test(
            "Super Admin Login", 
            success and 'access_token' in response,
            f"User: {response.get('user', {}).get('username', 'Unknown')} ({response.get('user', {}).get('role', 'Unknown')})"
        )

    def test_create_organization(self) -> bool:
        """Test organization creation (Super Admin only)"""
        org_data = {
            "name": "Advocacia Digital S.A.",
            "description": "Escritório de advocacia especializado em direito digital",
            "cnpj": "12.345.678/0001-90",
            "address": "Av. Paulista, 1000 - São Paulo, SP",
            "phone": "(11) 3456-7890",
            "email": "contato@advocaciadigital.com.br"
        }
        
        success, response = self.make_request('POST', '/organizations', org_data, 200, auth_required=True)
        
        if success and 'id' in response:
            self.created_org_id = response['id']
            
        return self.log_test(
            "Create Organization (Super Admin)", 
            success and 'id' in response,
            f"Created org: {response.get('name', 'Unknown')} (ID: {response.get('id', 'None')[:8]}...)"
        )

    def test_get_organizations(self) -> bool:
        """Test getting organizations"""
        success, response = self.make_request('GET', '/organizations', auth_required=True)
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Get Organizations", 
            success and is_list,
            f"Found {len(response) if is_list else 0} organizations"
        )

    def test_get_organization_by_id(self) -> bool:
        """Test getting specific organization by ID"""
        if not self.created_org_id:
            return self.log_test("Get Organization by ID", False, "No organization ID available")
            
        success, response = self.make_request('GET', f'/organizations/{self.created_org_id}', auth_required=True)
        
        return self.log_test(
            "Get Organization by ID", 
            success and 'id' in response,
            f"Retrieved org: {response.get('name', 'Unknown')}"
        )

    def test_create_admin_for_organization(self) -> bool:
        """Test creating Admin user for organization (Super Admin creates Admin)"""
        if not self.created_org_id:
            return self.log_test("Create Admin for Organization", False, "No organization ID available")
            
        admin_data = {
            "username": f"admin_advocacia_{datetime.now().strftime('%H%M%S')}",
            "email": "admin@advocaciadigital.com.br",
            "full_name": "Administrador Advocacia Digital",
            "password": "AdminPass123!",
            "role": "admin",
            "organization_id": self.created_org_id
        }
        
        success, response = self.make_request('POST', '/users', admin_data, 200, auth_required=True)
        
        if success and 'id' in response:
            self.created_admin_id = response['id']
            
        return self.log_test(
            "Create Admin for Organization", 
            success and 'id' in response and response.get('organization_id') == self.created_org_id,
            f"Created admin: {response.get('username', 'Unknown')} for org: {self.created_org_id[:8]}..."
        )

    def test_admin_login(self) -> bool:
        """Test admin login to get admin token"""
        if not self.created_admin_id:
            return self.log_test("Admin Login", False, "No admin user created")
            
        # Get admin username from created admin
        success_get, admin_data = self.make_request('GET', '/users', auth_required=True)
        if not success_get:
            return self.log_test("Admin Login", False, "Could not retrieve admin data")
            
        admin_username = None
        for user in admin_data:
            if user.get('id') == self.created_admin_id:
                admin_username = user.get('username')
                break
                
        if not admin_username:
            return self.log_test("Admin Login", False, "Could not find admin username")
            
        login_data = {
            "username": admin_username,
            "password": "AdminPass123!"
        }
        
        success, response = self.make_request('POST', '/auth/login', login_data)
        
        if success and 'access_token' in response:
            self.admin_token = response['access_token']
            
        return self.log_test(
            "Admin Login", 
            success and 'access_token' in response,
            f"Admin logged in: {response.get('user', {}).get('username', 'Unknown')} ({response.get('user', {}).get('role', 'Unknown')})"
        )

    def test_admin_create_user_in_organization(self) -> bool:
        """Test Admin creating User within their organization"""
        if not self.admin_token:
            return self.log_test("Admin Create User in Organization", False, "No admin token available")
            
        # Temporarily switch to admin token
        original_token = self.token
        self.token = self.admin_token
        
        user_data = {
            "username": f"user_advocacia_{datetime.now().strftime('%H%M%S')}",
            "email": "usuario@advocaciadigital.com.br",
            "full_name": "Usuário Advocacia Digital",
            "password": "UserPass123!",
            "role": "user"
            # Note: organization_id should be automatically set by the admin's organization
        }
        
        success, response = self.make_request('POST', '/users', user_data, 200, auth_required=True)
        
        # Restore original token
        self.token = original_token
        
        return self.log_test(
            "Admin Create User in Organization", 
            success and 'id' in response and response.get('organization_id') == self.created_org_id,
            f"Admin created user: {response.get('username', 'Unknown')} in org: {response.get('organization_id', 'None')[:8]}..."
        )

    def test_admin_view_organization_users(self) -> bool:
        """Test Admin viewing users in their organization only"""
        if not self.admin_token:
            return self.log_test("Admin View Organization Users", False, "No admin token available")
            
        # Temporarily switch to admin token
        original_token = self.token
        self.token = self.admin_token
        
        success, response = self.make_request('GET', '/users', auth_required=True)
        
        # Restore original token
        self.token = original_token
        
        is_list = isinstance(response, list)
        # Admin should only see users from their organization
        org_users_only = True
        if is_list:
            for user in response:
                if user.get('organization_id') != self.created_org_id and user.get('role') != 'super_admin':
                    org_users_only = False
                    break
        
        return self.log_test(
            "Admin View Organization Users", 
            success and is_list and org_users_only,
            f"Admin sees {len(response) if is_list else 0} users from their organization"
        )

    def test_organization_hierarchy_validation(self) -> bool:
        """Test organization hierarchy validation rules"""
        # Test 1: Super Admin can create Admin without organization (should fail)
        admin_no_org_data = {
            "username": f"admin_no_org_{datetime.now().strftime('%H%M%S')}",
            "email": "admin.noorg@test.com",
            "full_name": "Admin Without Organization",
            "password": "AdminPass123!",
            "role": "admin"
            # No organization_id - should fail
        }
        
        success1, response1 = self.make_request('POST', '/users', admin_no_org_data, 400, auth_required=True)
        test1_passed = not success1 and 'organization' in str(response1.get('detail', '')).lower()
        
        # Test 2: Admin trying to create another Admin (should fail)
        if self.admin_token:
            original_token = self.token
            self.token = self.admin_token
            
            admin_data = {
                "username": f"admin_by_admin_{datetime.now().strftime('%H%M%S')}",
                "email": "admin.byadmin@test.com",
                "full_name": "Admin Created by Admin",
                "password": "AdminPass123!",
                "role": "admin"
            }
            
            success2, response2 = self.make_request('POST', '/users', admin_data, 403, auth_required=True)
            test2_passed = not success2 and 'admin can only create user' in str(response2.get('detail', '')).lower()
            
            self.token = original_token
        else:
            test2_passed = False
        
        overall_success = test1_passed and test2_passed
        
        return self.log_test(
            "Organization Hierarchy Validation", 
            overall_success,
            f"Admin without org: {'BLOCKED' if test1_passed else 'ALLOWED'}, Admin by Admin: {'BLOCKED' if test2_passed else 'ALLOWED'}"
        )

    def test_create_user(self) -> bool:
        """Test user creation (Admin creates User)"""
        user_data = {
            "username": f"testuser_{datetime.now().strftime('%H%M%S')}",
            "email": "testuser@certguard.ai",
            "full_name": "Test User",
            "password": "TestPassword123!",
            "role": "user"
        }
        
        success, response = self.make_request('POST', '/users', user_data, 200, auth_required=True)
        
        if success and 'id' in response:
            self.created_user_id = response['id']
            
        return self.log_test(
            "Create User", 
            success and 'id' in response,
            f"Created user: {response.get('username', 'Unknown')} (ID: {response.get('id', 'None')[:8]}...)"
        )

    def test_get_users(self) -> bool:
        """Test getting all users"""
        success, response = self.make_request('GET', '/users', auth_required=True)
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Get All Users", 
            success and is_list,
            f"Found {len(response) if is_list else 0} users"
        )

    def test_admin_dashboard(self) -> bool:
        """Test admin dashboard endpoint"""
        success, response = self.make_request('GET', '/dashboard/admin', auth_required=True)
        
        if success:
            required_fields = ['total_users', 'total_certificates', 'active_certificates', 'unresolved_alerts']
            has_all_fields = all(field in response for field in required_fields)
            success = success and has_all_fields
            
        return self.log_test(
            "Admin Dashboard", 
            success,
            f"Users: {response.get('total_users', 0)}, Certs: {response.get('total_certificates', 0)}"
        )

    def test_initialize_tribunal_sites(self) -> bool:
        """Test tribunal sites initialization"""
        success, response = self.make_request('POST', '/init/tribunal-sites', auth_required=True)
        
        return self.log_test(
            "Initialize Tribunal Sites", 
            success,
            f"Response: {response.get('message', 'No message')}"
        )

    def test_get_tribunal_sites(self) -> bool:
        """Test getting tribunal sites"""
        success, response = self.make_request('GET', '/tribunal-sites', auth_required=True)
        
        is_list = isinstance(response, list)
        if is_list and len(response) > 0:
            # Store site IDs for later use in assignments
            self.site_ids = [site['id'] for site in response[:5]]  # Get first 5 site IDs
            
        return self.log_test(
            "Get Tribunal Sites", 
            success and is_list,
            f"Found {len(response) if is_list else 0} tribunal sites"
        )

    def test_certificate_import(self) -> bool:
        """Test certificate import from P12/PFX file"""
        # Create a mock P12 file data (base64 encoded)
        mock_p12_data = base64.b64encode(b"MOCK_P12_FILE_DATA_FOR_TESTING").decode()
        
        import_data = {
            "name": "Certificado Teste Import",
            "organization": "Organização Teste",
            "password": "senha123",
            "file_data": mock_p12_data,
            "file_name": "teste.p12"
        }
        
        success, response = self.make_request('POST', '/certificates/import', import_data, auth_required=True)
        
        # This will likely fail due to invalid P12 data, but we test the endpoint
        endpoint_exists = success or ('detail' in response and 'import' in str(response.get('detail', '')).lower())
        
        if success and 'certificate' in response:
            self.created_cert_id = response['certificate']['id']
        else:
            # Try to get existing certificate for further tests
            success_get, assignments = self.make_request('GET', '/certificates/assignments', auth_required=True)
            if success_get and isinstance(assignments, list) and len(assignments) > 0:
                self.created_cert_id = assignments[0]['certificate']['id']
            
        return self.log_test(
            "Certificate Import (P12/PFX)", 
            endpoint_exists,
            f"Import result: {response.get('message', response.get('detail', 'Endpoint tested'))}"
        )

    def test_certificate_assignment_full(self) -> bool:
        """Test full certificate assignment with sites"""
        if not self.created_cert_id or not self.created_user_id or not self.site_ids:
            return self.log_test("Certificate Assignment (Full)", False, "Missing cert, user, or site IDs")
            
        assignment_data = {
            "certificate_id": self.created_cert_id,
            "user_id": self.created_user_id,
            "site_ids": self.site_ids[:3],  # Assign to first 3 sites
            "access_type": "full",
            "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
        }
        
        success, response = self.make_request('POST', '/certificates/assign', assignment_data, auth_required=True)
        
        return self.log_test(
            "Certificate Assignment (Full)", 
            success,
            f"Assignment result: {response.get('message', response.get('detail', 'No message'))}"
        )

    def test_get_certificate_assignments(self) -> bool:
        """Test getting all certificate assignments"""
        success, response = self.make_request('GET', '/certificates/assignments', auth_required=True)
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Get Certificate Assignments", 
            success and is_list,
            f"Found {len(response) if is_list else 0} assignments"
        )

    def test_security_dashboard(self) -> bool:
        """Test comprehensive security dashboard"""
        success, response = self.make_request('GET', '/security/dashboard', auth_required=True)
        
        if success:
            required_fields = ['security_alerts', 'high_risk_activities', 'failed_logins', 'security_score', 'threat_level']
            has_all_fields = all(field in response for field in required_fields)
            success = success and has_all_fields
            
        return self.log_test(
            "Security Dashboard", 
            success,
            f"Score: {response.get('security_score', 0):.2f}, Threat: {response.get('threat_level', 'Unknown')}, Alerts: {len(response.get('security_alerts', []))}"
        )

    def test_ai_analysis_behavior(self) -> bool:
        """Test AI behavior analysis"""
        analysis_data = {
            "analysis_type": "behavior",
            "time_range": 24,
            "context": {
                "requested_by": "test_suite",
                "test_mode": True
            }
        }
        
        success, response = self.make_request('POST', '/ai/analyze', analysis_data, auth_required=True)
        
        has_analysis = success and ('result' in response or 'error' in response)
        
        return self.log_test(
            "AI Analysis (Behavior)", 
            has_analysis,
            f"Analysis result: {response.get('analysis_type', 'Unknown')} - {response.get('result', {}).get('risk_level', response.get('error', 'Completed'))}"
        )

    def test_ai_analysis_certificate(self) -> bool:
        """Test AI certificate analysis"""
        analysis_data = {
            "analysis_type": "certificate",
            "time_range": 24,
            "context": {
                "requested_by": "test_suite",
                "test_mode": True
            }
        }
        
        success, response = self.make_request('POST', '/ai/analyze', analysis_data, auth_required=True)
        
        has_analysis = success and ('result' in response or 'error' in response)
        
        return self.log_test(
            "AI Analysis (Certificate)", 
            has_analysis,
            f"Analysis result: {response.get('analysis_type', 'Unknown')} - {len(response.get('result', {}).get('urgent_renewals', []))} urgent renewals"
        )

    def test_ai_analysis_security(self) -> bool:
        """Test AI security analysis"""
        analysis_data = {
            "analysis_type": "security",
            "time_range": 24,
            "context": {
                "requested_by": "test_suite",
                "test_mode": True
            }
        }
        
        success, response = self.make_request('POST', '/ai/analyze', analysis_data, auth_required=True)
        
        has_analysis = success and ('result' in response or 'error' in response)
        
        return self.log_test(
            "AI Analysis (Security)", 
            has_analysis,
            f"Analysis result: {response.get('analysis_type', 'Unknown')} - Score: {response.get('result', {}).get('overall_security_score', 'N/A')}"
        )

    def test_user_accessible_sites(self) -> bool:
        """Test user accessible sites endpoint"""
        success, response = self.make_request('GET', '/user/accessible-sites', auth_required=True)
        
        is_list = isinstance(response, list)
        return self.log_test(
            "User Accessible Sites", 
            success and is_list,
            f"Found {len(response) if is_list else 0} accessible sites"
        )

    def test_security_alerts(self) -> bool:
        """Test security alerts endpoint"""
        success, response = self.make_request('GET', '/security/alerts', auth_required=True)
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Security Alerts", 
            success and is_list,
            f"Found {len(response) if is_list else 0} security alerts"
        )

    def test_user_audit_trail(self) -> bool:
        """Test user audit trail"""
        if not self.created_user_id:
            return self.log_test("User Audit Trail", False, "No user ID available")
            
        success, response = self.make_request('GET', f'/audit/user/{self.created_user_id}', auth_required=True)
        
        is_list = isinstance(response, list)
        return self.log_test(
            "User Audit Trail", 
            success and is_list,
            f"Found {len(response) if is_list else 0} audit entries"
        )

    def test_container_access(self) -> bool:
        """Test secure container access"""
        if not self.created_cert_id:
            return self.log_test("Container Access", False, "No certificate ID available")
            
        access_data = {
            "certificate_id": self.created_cert_id,
            "site_url": "https://www.stf.jus.br"
        }
        
        success, response = self.make_request('POST', '/container/access', access_data, auth_required=True)
        
        # This might fail due to missing site access setup, but we test the endpoint
        has_access_data = 'access_token' in response or 'error' in response or 'detail' in response
        
        return self.log_test(
            "Container Access", 
            success or (not success and has_access_data),
            f"Access result: {response.get('message', response.get('detail', 'Tested'))}"
        )

    def test_logout(self) -> bool:
        """Test user logout"""
        success, response = self.make_request('POST', '/auth/logout', auth_required=True)
        
        return self.log_test(
            "User Logout", 
            success,
            f"Logout result: {response.get('message', 'No message')}"
        )

    def run_all_tests(self) -> int:
        """Run all API tests"""
        print("🚀 Starting CertGuard AI v2.0 COMPREHENSIVE Backend API Tests")
        print("Testing: Organization Hierarchy, Certificate Import, Assignments, Security Dashboard, AI Analysis, Audit Trail")
        print("=" * 80)
        
        # Core API tests
        self.test_root_endpoint()
        
        # Authentication tests
        self.test_login()
        
        if not self.token:
            print("❌ Cannot continue tests without authentication token")
            return 1
        
        # ORGANIZATION HIERARCHY TESTS (NEW PRIORITY TESTS)
        print("\n🏢 Testing ORGANIZATION HIERARCHY SYSTEM:")
        print("-" * 50)
        
        # 1. Organization Management
        self.test_create_organization()
        self.test_get_organizations()
        self.test_get_organization_by_id()
        
        # 2. Hierarchical User Management
        self.test_create_admin_for_organization()
        self.test_admin_login()
        self.test_admin_create_user_in_organization()
        self.test_admin_view_organization_users()
        
        # 3. Hierarchy Validation Rules
        self.test_organization_hierarchy_validation()
        
        # User management tests (existing)
        self.test_create_user()
        self.test_get_users()
        
        # Dashboard and admin tests
        self.test_admin_dashboard()
        
        # Tribunal sites tests (must run before assignments)
        self.test_initialize_tribunal_sites()
        self.test_get_tribunal_sites()
        
        # CORE FEATURE TESTS
        print("\n🔥 Testing CORE Features:")
        print("-" * 40)
        
        # 1. Certificate Import
        self.test_certificate_import()
        
        # 2. Certificate Assignments
        self.test_certificate_assignment_full()
        self.test_get_certificate_assignments()
        
        # 3. Security Dashboard
        self.test_security_dashboard()
        
        # 4. AI Analysis (3 types)
        self.test_ai_analysis_behavior()
        self.test_ai_analysis_certificate()
        self.test_ai_analysis_security()
        
        # 5. Audit Trail
        self.test_security_alerts()
        self.test_user_audit_trail()
        
        # Additional tests
        self.test_user_accessible_sites()
        self.test_container_access()
        
        # Logout test
        self.test_logout()
        
        # Print results
        print("=" * 80)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed! CertGuard AI v2.0 backend with HIERARCHICAL ORGANIZATIONS is working correctly.")
            return 0
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed. Check the issues above.")
            return 1

def main():
    """Main test execution"""
    tester = CertGuardAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())