#!/usr/bin/env python3
"""
Backend API Testing for Red Team Automation Framework v3.1
Tests all API endpoints with Tactical Decision Engine and MITRE ATT&CK integration
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

class RedTeamAPITester:
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
        """Test API health check - should return v3.1.0 with tactical_engine features"""
        success, response = self.run_test(
            "API Health Check",
            "GET", 
            "",  # Root endpoint
            200
        )
        
        if success and "message" in response:
            self.log(f"API Message: {response['message']}")
            version = response.get('version', 'unknown')
            features = response.get('features', [])
            self.log(f"Version: {version}")
            self.log(f"Features: {features}")
            
            # Verify v3.1.0 and tactical_engine feature
            if version == "3.1.0" and "tactical_engine" in features:
                self.log("✅ Correct version and tactical_engine feature present")
                return True
            else:
                self.log(f"❌ Expected v3.1.0 with tactical_engine, got {version} with {features}")
                return False
        return False
    
    def test_mitre_tactics(self) -> bool:
        """Test MITRE ATT&CK tactics endpoint"""
        success, response = self.run_test(
            "Get MITRE ATT&CK Tactics",
            "GET",
            "mitre/tactics",
            200
        )
        
        if success and "tactics" in response:
            tactics = response["tactics"]
            self.log(f"Found {len(tactics)} MITRE ATT&CK tactics")
            
            # Verify key tactics exist
            expected_tactics = ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation"]
            for tactic in expected_tactics:
                if tactic in tactics:
                    tactic_info = tactics[tactic]
                    self.log(f"  - {tactic_info.get('name', tactic)} ({tactic_info.get('id', 'N/A')})")
                else:
                    self.log(f"❌ Missing expected tactic: {tactic}")
                    return False
            return True
        return False
    
    def test_get_tools(self) -> bool:
        """Test getting available tools by phase"""
        success, response = self.run_test(
            "Get All Tools",
            "GET",
            "tools",
            200
        )
        
        if success and "tools" in response:
            tools = response["tools"]
            self.log(f"Found {len(tools)} tools available")
            
            # Test specific phase
            success2, response2 = self.run_test(
                "Get Reconnaissance Tools",
                "GET",
                "tools?phase=reconnaissance",
                200
            )
            
            if success2 and "tools" in response2:
                recon_tools = response2["tools"]
                self.log(f"Found {len(recon_tools)} reconnaissance tools")
                for tool_name, tool_info in list(recon_tools.items())[:3]:
                    self.log(f"  - {tool_name}: {tool_info.get('desc', 'No description')}")
                return True
        return False
    
    def test_tactical_waf_bypass(self) -> bool:
        """Test tactical WAF bypass strategies"""
        # Test Cloudflare bypass
        success1, response1 = self.run_test(
            "Get Cloudflare WAF Bypass Strategy",
            "GET",
            "tactical/waf-bypass/cloudflare",
            200
        )
        
        if success1:
            self.log(f"Cloudflare bypass techniques: {len(response1.get('techniques', []))}")
            if response1.get('name') == 'Cloudflare':
                self.log("✅ Cloudflare strategy found")
            else:
                self.log("❌ Invalid Cloudflare strategy")
                return False
        else:
            return False
        
        # Test Akamai bypass
        success2, response2 = self.run_test(
            "Get Akamai WAF Bypass Strategy",
            "GET",
            "tactical/waf-bypass/akamai",
            200
        )
        
        if success2:
            self.log(f"Akamai bypass techniques: {len(response2.get('techniques', []))}")
            if response2.get('name') == 'Akamai':
                self.log("✅ Akamai strategy found")
                return True
            else:
                self.log("❌ Invalid Akamai strategy")
                return False
        return False
    
    def test_tactical_service_attacks(self) -> bool:
        """Test service-specific attack strategies"""
        success, response = self.run_test(
            "Get Service Attack Strategies",
            "GET",
            "tactical/service-attacks",
            200
        )
        
        if success and "strategies" in response:
            strategies = response["strategies"]
            self.log(f"Found {len(strategies)} service attack strategies")
            
            # Check for key services
            expected_services = ["ssh", "http", "smb", "rdp", "mysql"]
            for service in expected_services:
                if service in strategies:
                    strategy = strategies[service]
                    self.log(f"  - {service}: {strategy.get('decision', 'No decision')}")
                else:
                    self.log(f"❌ Missing strategy for {service}")
                    return False
            return True
        return False
    
    def test_tactical_vuln_exploits(self) -> bool:
        """Test vulnerability to exploit mapping"""
        success, response = self.run_test(
            "Get Vulnerability Exploit Mappings",
            "GET",
            "tactical/vuln-exploits",
            200
        )
        
        if success and "mappings" in response:
            mappings = response["mappings"]
            self.log(f"Found {len(mappings)} vulnerability exploit mappings")
            
            # Check for critical vulnerabilities
            expected_vulns = ["sql injection", "xss", "lfi", "command injection", "eternalblue"]
            for vuln in expected_vulns:
                if vuln in mappings:
                    mapping = mappings[vuln]
                    self.log(f"  - {vuln}: {mapping.get('severity', 'unknown')} severity")
                else:
                    self.log(f"❌ Missing mapping for {vuln}")
                    return False
            return True
        return False
        """Test Metasploit modules endpoint"""
        success, response = self.run_test(
            "Get Metasploit Modules",
            "GET",
            "metasploit/modules",
            200
        )
        
        if success and "modules" in response:
            modules = response["modules"]
            self.log(f"Found {len(modules)} Metasploit modules")
            
            # Test filtering by category
            success2, response2 = self.run_test(
                "Get Exploit Modules",
                "GET",
                "metasploit/modules?category=exploit",
                200
            )
            
            if success2 and "modules" in response2:
                exploit_modules = response2["modules"]
                self.log(f"Found {len(exploit_modules)} exploit modules")
                
                # Show some examples
                for module in exploit_modules[:3]:
                    self.log(f"  - {module.get('name', 'Unknown')}: {module.get('desc', 'No description')}")
                
                # Verify we have 35+ modules total
                if len(modules) >= 35:
                    self.log("✅ Has 35+ Metasploit modules as expected")
                    return True
                else:
                    self.log(f"❌ Expected 35+ modules, found {len(modules)}")
                    return False
        return False
    
    def test_start_scan(self) -> bool:
        """Test starting a new scan with MITRE phases"""
        test_data = {
            "target": "example.com",
            "scan_phases": ["reconnaissance", "initial_access"],
            "tools": []
        }
        
        success, response = self.run_test(
            "Start New Red Team Operation",
            "POST",
            "scan/start",
            200,
            test_data
        )
        
        if success and "scan_id" in response:
            self.scan_id = response["scan_id"]
            self.log(f"Operation started with ID: {self.scan_id}")
            self.log(f"Target: {response.get('target', 'unknown')}")
            self.log(f"Phases: {response.get('phases', [])}")
            return True
        return False
    
    def test_scan_status_with_tactical(self) -> bool:
        """Test getting scan status with tactical decisions"""
        if not self.scan_id:
            self.log("No scan ID available for status test", "ERROR")
            return False
        
        success, response = self.run_test(
            "Get Operation Status with Tactical Decisions",
            "GET",
            f"scan/{self.scan_id}/status",
            200
        )
        
        if success:
            self.log(f"Operation Status: {response.get('status', 'unknown')}")
            self.log(f"Progress: {response.get('progress', 0)}%")
            if response.get('current_tool'):
                self.log(f"Current Tool: {response['current_tool']}")
            
            # Check for tactical decisions
            tactical_decisions = response.get('tactical_decisions', [])
            if tactical_decisions:
                self.log(f"✅ Found {len(tactical_decisions)} tactical decisions")
                for i, decision in enumerate(tactical_decisions[:2]):  # Show first 2
                    advice = decision.get('advice', {})
                    self.log(f"  Decision {i+1}: {advice.get('overall_strategy', 'No strategy')[:50]}...")
            else:
                self.log("⚠️ No tactical decisions found yet")
            
            # Check for final tactical analysis
            final_tactical = response.get('final_tactical')
            if final_tactical:
                self.log("✅ Final tactical analysis present")
                waf_analysis = final_tactical.get('waf_analysis')
                if waf_analysis:
                    self.log(f"  WAF detected: {waf_analysis.get('waf_detected', False)}")
                port_decisions = final_tactical.get('port_decisions', [])
                if port_decisions:
                    self.log(f"  Port decisions: {len(port_decisions)}")
            
            return True
        return False
    
    def test_metasploit_modules(self) -> bool:
        """Test Metasploit modules endpoint"""
        success, response = self.run_test(
            "Get Metasploit Modules",
            "GET",
            "metasploit/modules",
            200
        )
        
        if success and "modules" in response:
            modules = response["modules"]
            self.log(f"Found {len(modules)} Metasploit modules")
            
            # Test filtering by category
            success2, response2 = self.run_test(
                "Get Exploit Modules",
                "GET",
                "metasploit/modules?category=exploit",
                200
            )
            
            if success2 and "modules" in response2:
                exploit_modules = response2["modules"]
                self.log(f"Found {len(exploit_modules)} exploit modules")
                
                # Show some examples
                for module in exploit_modules[:3]:
                    self.log(f"  - {module.get('name', 'Unknown')}: {module.get('desc', 'No description')}")
                
                # Verify we have modules
                if len(modules) >= 5:
                    self.log("✅ Has sufficient Metasploit modules")
                    return True
                else:
                    self.log(f"❌ Expected 5+ modules, found {len(modules)}")
                    return False
        return False

    def test_attack_tree(self) -> bool:
        """Test attack tree generation and retrieval"""
        if not self.scan_id:
            self.log("No scan ID available for attack tree test", "ERROR")
            return False
        
        success, response = self.run_test(
            "Get Attack Tree",
            "GET",
            f"scan/{self.scan_id}/tree",
            200
        )
        
        if success:
            if "root" in response and "nodes" in response:
                root = response["root"]
                nodes = response["nodes"]
                self.log(f"Attack tree retrieved - Root: {root.get('name', 'Unknown')}")
                self.log(f"Total nodes: {len(nodes)}")
                
                # Show some node types
                node_types = {}
                for node in nodes.values():
                    node_type = node.get('type', 'unknown')
                    node_types[node_type] = node_types.get(node_type, 0) + 1
                
                for node_type, count in node_types.items():
                    self.log(f"  - {node_type}: {count} nodes")
                
                return True
            else:
                self.log("❌ Invalid attack tree structure")
                return False
        return False
    
    def test_metasploit_execution(self) -> bool:
        """Test Metasploit exploit execution"""
        test_data = {
            "scan_id": self.scan_id or "",
            "node_id": "test_node",
            "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
            "target_host": "example.com",
            "target_port": 80,
            "options": {},
            "lhost": "192.168.1.100",
            "lport": 4444
        }
        
        success, response = self.run_test(
            "Execute Metasploit Module",
            "POST",
            "metasploit/execute",
            200,
            test_data
        )
        
        if success:
            self.log(f"Module: {response.get('module', 'unknown')}")
            self.log(f"Target: {response.get('target', 'unknown')}")
            self.log(f"Success: {response.get('success', False)}")
            self.log(f"Session Opened: {response.get('session_opened', False)}")
            
            if response.get('simulated'):
                self.log("✅ Simulated execution (expected for testing)")
            
            return True
        return False
    
    def test_scan_history(self) -> bool:
        """Test getting scan history"""
        success, response = self.run_test(
            "Get Operation History",
            "GET",
            "scan/history",
            200
        )
        
        if success:
            if isinstance(response, list):
                self.log(f"Found {len(response)} operations in history")
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
            "Get Operation Report",
            "GET",
            f"scan/{self.scan_id}/report",
            200
        )
        
        if success and "report" in response:
            self.log("Operation report retrieved successfully")
            report = response["report"]
            if "ai_analysis" in report:
                self.log("✅ AI analysis included in report")
            if "attack_tree" in report:
                self.log("✅ Attack tree included in report")
            return True
        return False
    
    def test_invalid_endpoints(self) -> bool:
        """Test invalid endpoints return proper errors"""
        tests = [
            ("Invalid Scan ID", "GET", "scan/invalid-id/status", 404, None),
            ("Invalid Target", "POST", "scan/start", 400, {"target": "", "scan_phases": []}),
            ("Nonexistent Report", "GET", "scan/nonexistent/report", 404, None),
            ("Invalid MITRE Tactic", "GET", "mitre/tactics/invalid", 404, None)
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
                        self.log("✅ Kimi K2 AI analysis present")
                        ai_text = response['ai_analysis'][:100] + "..." if len(response['ai_analysis']) > 100 else response['ai_analysis']
                        self.log(f"AI Analysis preview: {ai_text}")
                    else:
                        self.log("⚠️ No AI analysis found")
                    
                    # Check exploit suggestions
                    exploits = response.get('exploits', [])
                    if exploits:
                        self.log(f"✅ Found {len(exploits)} exploit recommendations")
                    else:
                        self.log("⚠️ No exploit recommendations found")
                    
                    # Check attack tree
                    if response.get('attack_tree'):
                        self.log("✅ Attack tree generated")
                    else:
                        self.log("⚠️ No attack tree found")
                    
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
            "Delete Operation",
            "DELETE",
            f"scan/{self.scan_id}",
            200
        )
        
        if success:
            self.log("Operation deleted successfully")
            return True
        return False
    
    def run_all_tests(self):
        """Run all backend tests"""
        self.log("=" * 60)
        self.log("RED TEAM AUTOMATION FRAMEWORK v3.1 - BACKEND TESTS")
        self.log("=" * 60)
        
        # Basic API tests
        self.log("\n🔍 TESTING BASIC API ENDPOINTS")
        self.test_health_check()
        
        # MITRE ATT&CK tests
        self.log("\n🎯 TESTING MITRE ATT&CK INTEGRATION")
        self.test_mitre_tactics()
        self.test_get_tools()
        
        # NEW: Tactical Decision Engine tests
        self.log("\n🧠 TESTING TACTICAL DECISION ENGINE v3.1")
        self.test_tactical_waf_bypass()
        self.test_tactical_service_attacks()
        self.test_tactical_vuln_exploits()
        
        # Metasploit tests
        self.log("\n💀 TESTING METASPLOIT INTEGRATION")
        self.test_metasploit_modules()
        
        # Scan workflow tests
        self.log("\n🔍 TESTING RED TEAM OPERATION WORKFLOW")
        if self.test_start_scan():
            self.test_scan_status_with_tactical()
            
            # Wait for scan completion to test AI integration
            self.log("\n🤖 TESTING KIMI K2 AI INTEGRATION")
            self.wait_for_scan_completion()
            
            # Test attack tree and metasploit
            self.log("\n🌳 TESTING ATTACK TREE & EXPLOITATION")
            self.test_attack_tree()
            self.test_metasploit_execution()
            
            self.test_scan_report()
        
        # History and management
        self.log("\n🔍 TESTING OPERATION MANAGEMENT")
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
    tester = RedTeamAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())