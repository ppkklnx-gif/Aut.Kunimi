#!/usr/bin/env python3
"""
Backend API Testing for Kali Pentesting Automation Suite
Tests all API endpoints and functionality
"""

import requests
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional

# Use the public endpoint from frontend .env
BACKEND_URL = "https://security-framework-3.preview.emergentagent.com"
API_BASE = f"{BACKEND_URL}/api"

class PentestAPITester:
    def __init__(self):
        self.tests_run = 0
        self.tests_passed = 0
        self.scan_id = None
        
    def log(self, message: str, level: str = "INFO"):
        """Log test messages"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    def run_test(self, name: str, method: str, endpoint: str, expected_status: int, 
                 data: Optional[Dict] = None, timeout: int = 30) -> tuple[bool, Dict]:
        """Run a single API test"""
        url = f"{API_BASE}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        self.log(f"Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                self.log(f"Unsupported method: {method}", "ERROR")
                return False, {}
            
            success = response.status_code == expected_status
            
            if success:
                self.tests_passed += 1
                self.log(f"✅ PASSED - Status: {response.status_code}")
                try:
                    return True, response.json()
                except:
                    return True, {"raw_response": response.text}
            else:
                self.log(f"❌ FAILED - Expected {expected_status}, got {response.status_code}", "ERROR")
                self.log(f"Response: {response.text[:200]}", "ERROR")
                return False, {}
                
        except requests.exceptions.Timeout:
            self.log(f"❌ FAILED - Request timed out after {timeout}s", "ERROR")
            return False, {}
        except requests.exceptions.ConnectionError:
            self.log(f"❌ FAILED - Connection error", "ERROR")
            return False, {}
        except Exception as e:
            self.log(f"❌ FAILED - Error: {str(e)}", "ERROR")
            return False, {}
    
    def test_health_check(self) -> bool:
        """Test API health check"""
        success, response = self.run_test(
            "API Health Check",
            "GET", 
            "",  # Root endpoint
            200
        )
        
        if success and "message" in response:
            self.log(f"API Message: {response['message']}")
            return True
        return False
    
    def test_get_tools(self) -> bool:
        """Test getting available tools"""
        success, response = self.run_test(
            "Get Available Tools",
            "GET",
            "tools",
            200
        )
        
        if success and "tools" in response:
            tools = response["tools"]
            self.log(f"Found {len(tools)} tools available")
            for tool in tools:
                self.log(f"  - {tool['name']}: {tool['description']}")
            return True
        return False
    
    def test_start_scan(self) -> bool:
        """Test starting a new scan"""
        test_data = {
            "target": "example.com",
            "scan_types": ["waf", "nmap", "nikto"]
        }
        
        success, response = self.run_test(
            "Start New Scan",
            "POST",
            "scan/start",
            200,
            test_data
        )
        
        if success and "scan_id" in response:
            self.scan_id = response["scan_id"]
            self.log(f"Scan started with ID: {self.scan_id}")
            self.log(f"Target: {response.get('target', 'unknown')}")
            self.log(f"Tools: {response.get('tools', [])}")
            return True
        return False
    
    def test_scan_status(self) -> bool:
        """Test getting scan status"""
        if not self.scan_id:
            self.log("No scan ID available for status test", "ERROR")
            return False
        
        success, response = self.run_test(
            "Get Scan Status",
            "GET",
            f"scan/{self.scan_id}/status",
            200
        )
        
        if success:
            self.log(f"Scan Status: {response.get('status', 'unknown')}")
            self.log(f"Progress: {response.get('progress', 0)}%")
            if response.get('current_tool'):
                self.log(f"Current Tool: {response['current_tool']}")
            return True
        return False
    
    def test_scan_history(self) -> bool:
        """Test getting scan history"""
        success, response = self.run_test(
            "Get Scan History",
            "GET",
            "scan/history",
            200
        )
        
        if success:
            if isinstance(response, list):
                self.log(f"Found {len(response)} scans in history")
                for scan in response[:3]:  # Show first 3
                    self.log(f"  - {scan.get('target', 'unknown')} ({scan.get('status', 'unknown')})")
            return True
        return False
    
    def test_scan_report(self) -> bool:
        """Test getting scan report"""
        if not self.scan_id:
            self.log("No scan ID available for report test", "ERROR")
            return False
        
        success, response = self.run_test(
            "Get Scan Report",
            "GET",
            f"scan/{self.scan_id}/report",
            200
        )
        
        if success and "report" in response:
            self.log("Scan report retrieved successfully")
            return True
        return False
    
    def test_invalid_endpoints(self) -> bool:
        """Test invalid endpoints return proper errors"""
        tests = [
            ("Invalid Scan ID", "GET", "scan/invalid-id/status", 404, None),
            ("Invalid Tool", "POST", "scan/start", 400, {"target": "", "scan_types": []}),
            ("Nonexistent Report", "GET", "scan/nonexistent/report", 404, None)
        ]
        
        all_passed = True
        for name, method, endpoint, expected_status, data in tests:
            success, _ = self.run_test(name, method, endpoint, expected_status, data)
            if not success:
                all_passed = False
        
        return all_passed
    
    def wait_for_scan_completion(self, max_wait: int = 120) -> bool:
        """Wait for scan to complete and test AI analysis"""
        if not self.scan_id:
            return False
        
        self.log(f"Waiting for scan completion (max {max_wait}s)...")
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            success, response = self.run_test(
                "Check Scan Progress",
                "GET",
                f"scan/{self.scan_id}/status",
                200
            )
            
            if success:
                status = response.get('status', 'unknown')
                progress = response.get('progress', 0)
                current_tool = response.get('current_tool')
                
                if current_tool:
                    self.log(f"Progress: {progress}% - Running: {current_tool}")
                
                if status == 'completed':
                    self.log("✅ Scan completed successfully!")
                    
                    # Check AI analysis
                    if response.get('ai_analysis'):
                        self.log("✅ AI analysis present")
                        ai_text = response['ai_analysis'][:100] + "..." if len(response['ai_analysis']) > 100 else response['ai_analysis']
                        self.log(f"AI Analysis preview: {ai_text}")
                    else:
                        self.log("⚠️ No AI analysis found")
                    
                    # Check exploit suggestions
                    exploits = response.get('exploit_suggestions', [])
                    if exploits:
                        self.log(f"✅ Found {len(exploits)} exploit suggestions")
                    else:
                        self.log("⚠️ No exploit suggestions found")
                    
                    return True
                    
                elif status == 'error':
                    self.log("❌ Scan failed with error", "ERROR")
                    return False
            
            time.sleep(5)  # Wait 5 seconds between checks
        
        self.log("⚠️ Scan did not complete within timeout", "WARNING")
        return False
    
    def test_delete_scan(self) -> bool:
        """Test deleting a scan"""
        if not self.scan_id:
            self.log("No scan ID available for delete test", "ERROR")
            return False
        
        success, response = self.run_test(
            "Delete Scan",
            "DELETE",
            f"scan/{self.scan_id}",
            200
        )
        
        if success:
            self.log("Scan deleted successfully")
            return True
        return False
    
    def run_all_tests(self):
        """Run all backend tests"""
        self.log("=" * 60)
        self.log("STARTING KALI PENTEST SUITE BACKEND TESTS")
        self.log("=" * 60)
        
        # Basic API tests
        self.log("\n🔍 TESTING BASIC API ENDPOINTS")
        self.test_health_check()
        self.test_get_tools()
        
        # Scan workflow tests
        self.log("\n🔍 TESTING SCAN WORKFLOW")
        if self.test_start_scan():
            self.test_scan_status()
            
            # Wait for scan completion to test AI integration
            self.log("\n🤖 TESTING AI INTEGRATION")
            self.wait_for_scan_completion()
            
            self.test_scan_report()
        
        # History and management
        self.log("\n🔍 TESTING SCAN MANAGEMENT")
        self.test_scan_history()
        
        # Error handling
        self.log("\n🔍 TESTING ERROR HANDLING")
        self.test_invalid_endpoints()
        
        # Cleanup
        if self.scan_id:
            self.log("\n🧹 CLEANUP")
            self.test_delete_scan()
        
        # Results
        self.log("\n" + "=" * 60)
        self.log("TEST RESULTS")
        self.log("=" * 60)
        self.log(f"Tests Run: {self.tests_run}")
        self.log(f"Tests Passed: {self.tests_passed}")
        self.log(f"Tests Failed: {self.tests_run - self.tests_passed}")
        self.log(f"Success Rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        if self.tests_passed == self.tests_run:
            self.log("🎉 ALL TESTS PASSED!", "SUCCESS")
            return 0
        else:
            self.log("❌ SOME TESTS FAILED", "ERROR")
            return 1

def main():
    """Main test runner"""
    tester = PentestAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())