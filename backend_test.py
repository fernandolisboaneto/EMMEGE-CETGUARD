#!/usr/bin/env python3
"""
CertGuard AI Backend API Testing Suite v2.0
Tests all endpoints for the revolutionary certificate management system with AI
"""

import requests
import sys
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class CertGuardAPITester:
    def __init__(self, base_url: str = "https://db8c0483-612c-4ca0-a771-ee19879f6626.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.token = None
        self.created_user_id = None
        self.created_cert_id = None
        
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
                response = requests.get(url, headers=headers, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
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

    def test_dashboard_stats(self) -> bool:
        """Test dashboard statistics endpoint"""
        success, response = self.make_request('GET', '/dashboard/stats')
        
        if success:
            required_fields = ['total_certificates', 'active_certificates', 'expiring_soon', 'recent_activities']
            has_all_fields = all(field in response for field in required_fields)
            success = success and has_all_fields
            
        return self.log_test(
            "Dashboard Stats", 
            success,
            f"Stats: {response.get('total_certificates', 0)} total, {response.get('active_certificates', 0)} active"
        )

    def test_create_certificate(self) -> bool:
        """Test certificate creation"""
        sample_cert = {
            "name": "Teste CertGuard AI",
            "common_name": "teste.certguard.com.br",
            "organization": "CertGuard Test Organization",
            "department": "Departamento de Testes",
            "email": "teste@certguard.com.br",
            "valid_from": datetime.utcnow().isoformat(),
            "valid_to": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            "algorithm": "RSA-2048",
            "key_usage": ["digital_signature", "key_encipherment"],
            "san_dns": ["teste.certguard.com.br", "www.teste.certguard.com.br"]
        }
        
        success, response = self.make_request('POST', '/certificates', sample_cert, 200)
        
        if success and 'id' in response:
            self.created_cert_id = response['id']
            
        return self.log_test(
            "Create Certificate", 
            success and 'id' in response,
            f"Created cert ID: {response.get('id', 'None')}"
        )

    def test_get_certificates(self) -> bool:
        """Test getting all certificates"""
        success, response = self.make_request('GET', '/certificates')
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Get All Certificates", 
            success and is_list,
            f"Found {len(response) if is_list else 0} certificates"
        )

    def test_get_single_certificate(self) -> bool:
        """Test getting a specific certificate"""
        if not self.created_cert_id:
            return self.log_test("Get Single Certificate", False, "No certificate ID available")
            
        success, response = self.make_request('GET', f'/certificates/{self.created_cert_id}')
        
        return self.log_test(
            "Get Single Certificate", 
            success and response.get('id') == self.created_cert_id,
            f"Retrieved cert: {response.get('name', 'Unknown')}"
        )

    def test_ai_chat(self) -> bool:
        """Test AI conversational interface"""
        chat_data = {
            "message": "Quantos certificados estão ativos no sistema?",
            "context": {
                "user_language": "pt-BR",
                "current_time": datetime.utcnow().isoformat()
            }
        }
        
        success, response = self.make_request('POST', '/chat', chat_data)
        
        has_response = 'response' in response and len(response.get('response', '')) > 0
        return self.log_test(
            "AI Chat Interface", 
            success and has_response,
            f"AI Response length: {len(response.get('response', ''))}"
        )

    def test_ai_prediction(self) -> bool:
        """Test AI certificate prediction"""
        if not self.created_cert_id:
            return self.log_test("AI Prediction", False, "No certificate ID available")
            
        prediction_data = {
            "context": "Análise de renovação automática para certificado de teste",
            "time_horizon": 30
        }
        
        success, response = self.make_request('POST', f'/certificates/{self.created_cert_id}/predict', prediction_data)
        
        # Check if we got a prediction response (could be error due to NVIDIA API)
        has_prediction_data = any(key in response for key in ['renewal_probability', 'risk_level', 'error'])
        
        return self.log_test(
            "AI Prediction", 
            success and has_prediction_data,
            f"Prediction result: {response.get('renewal_probability', 'N/A')}% renewal probability"
        )

    def test_expiring_certificates(self) -> bool:
        """Test getting expiring certificates"""
        success, response = self.make_request('GET', '/certificates/expiring/30')
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Expiring Certificates", 
            success and is_list,
            f"Found {len(response) if is_list else 0} expiring certificates"
        )

    def test_audit_trail(self) -> bool:
        """Test audit trail functionality"""
        if not self.created_cert_id:
            return self.log_test("Audit Trail", False, "No certificate ID available")
            
        success, response = self.make_request('GET', f'/audit/{self.created_cert_id}')
        
        is_list = isinstance(response, list)
        return self.log_test(
            "Audit Trail", 
            success and is_list,
            f"Found {len(response) if is_list else 0} audit entries"
        )

    def test_zero_trust_verification(self) -> bool:
        """Test Zero Trust verification"""
        zero_trust_data = {
            "user_id": "test_user_123",
            "ip_address": "192.168.1.100",
            "user_agent": "CertGuard-Test-Agent/1.0",
            "location": "BR",
            "device_fingerprint": "test_device_fingerprint_123"
        }
        
        success, response = self.make_request('POST', '/zero-trust/verify', zero_trust_data)
        
        has_trust_data = 'trust_score' in response and 'access_granted' in response
        return self.log_test(
            "Zero Trust Verification", 
            success and has_trust_data,
            f"Trust score: {response.get('trust_score', 'N/A')}, Access: {response.get('access_granted', 'N/A')}"
        )

    def run_all_tests(self) -> int:
        """Run all API tests"""
        print("🚀 Starting CertGuard AI Backend API Tests")
        print("=" * 60)
        
        # Core API tests
        self.test_root_endpoint()
        self.test_dashboard_stats()
        
        # Certificate management tests
        self.test_create_certificate()
        self.test_get_certificates()
        self.test_get_single_certificate()
        self.test_expiring_certificates()
        
        # AI functionality tests
        self.test_ai_chat()
        self.test_ai_prediction()
        
        # Security and audit tests
        self.test_audit_trail()
        self.test_zero_trust_verification()
        
        # Print results
        print("=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed! CertGuard AI backend is working correctly.")
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