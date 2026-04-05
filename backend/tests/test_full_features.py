"""
Comprehensive test suite for Red Team Automation Framework v5.0
Tests all major features: Dashboard, Config, Scans, Chains, C2, Navigation
"""
import pytest
import requests
import os
import time

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://security-framework-3.preview.emergentagent.com').rstrip('/')

class TestHealthAndConfig:
    """Health check and global config tests"""
    
    def test_health_check(self):
        """GET /api/ - Health check returns version 5.0.0"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["version"] == "5.0.0"
        assert "features" in data
        print(f"SUCCESS: Health check - version {data['version']}")
    
    def test_get_config(self):
        """GET /api/config - Returns global operator config"""
        response = requests.get(f"{BASE_URL}/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "listener_ip" in data
        assert "listener_port" in data
        assert "c2_protocol" in data
        assert "operator_name" in data
        assert "auto_lhost" in data
        print(f"SUCCESS: Config retrieved - LHOST={data.get('listener_ip')}, LPORT={data.get('listener_port')}")
    
    def test_update_config(self):
        """PUT /api/config - Updates and persists config"""
        # First get current config
        current = requests.get(f"{BASE_URL}/api/config").json()
        
        # Update with test values
        test_config = {
            "listener_ip": "192.168.1.100",
            "listener_port": 5555,
            "c2_protocol": "https",
            "operator_name": "test_operator",
            "stealth_mode": True,
            "auto_lhost": True
        }
        response = requests.put(f"{BASE_URL}/api/config", json=test_config)
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") in ["saved", "updated"]
        
        # Verify persistence
        verify = requests.get(f"{BASE_URL}/api/config").json()
        assert verify["listener_ip"] == "192.168.1.100"
        assert verify["listener_port"] == 5555
        print(f"SUCCESS: Config updated and persisted - LHOST={verify['listener_ip']}")
        
        # Restore original config
        requests.put(f"{BASE_URL}/api/config", json=current)


class TestMITRETactics:
    """MITRE ATT&CK tactics and phases tests"""
    
    def test_get_mitre_tactics(self):
        """GET /api/mitre/tactics - Returns MITRE tactics dictionary"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics")
        assert response.status_code == 200
        data = response.json()
        assert "tactics" in data
        tactics = data["tactics"]
        
        # Should have multiple tactics
        assert len(tactics) >= 10
        
        # Check for key phases
        expected_phases = ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation"]
        for phase in expected_phases:
            assert phase in tactics, f"Missing phase: {phase}"
        
        print(f"SUCCESS: MITRE tactics - {len(tactics)} phases returned")


class TestScanOperations:
    """Scan start, status, and completion tests"""
    
    def test_start_scan(self):
        """POST /api/scan/start - Starts a scan and returns scan_id"""
        payload = {
            "target": "test.example.com",
            "scan_phases": ["reconnaissance"],
            "tools": []
        }
        response = requests.post(f"{BASE_URL}/api/scan/start", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["scan_id"] is not None
        print(f"SUCCESS: Scan started - scan_id={data['scan_id']}")
        return data["scan_id"]
    
    def test_scan_status_and_completion(self):
        """GET /api/scan/{id}/status - Returns scan progress and completes"""
        # Start a scan
        payload = {
            "target": "scantest.example.com",
            "scan_phases": ["reconnaissance"],
            "tools": []
        }
        start_response = requests.post(f"{BASE_URL}/api/scan/start", json=payload)
        scan_id = start_response.json()["scan_id"]
        
        # Poll for completion (max 15 seconds)
        max_wait = 15
        start_time = time.time()
        final_status = None
        
        while time.time() - start_time < max_wait:
            response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
            assert response.status_code == 200
            data = response.json()
            
            assert "status" in data
            assert "progress" in data
            
            if data["status"] == "completed":
                final_status = data
                break
            
            time.sleep(1)
        
        assert final_status is not None, "Scan did not complete in time"
        assert final_status["status"] == "completed"
        assert final_status["progress"] == 100
        
        # Check for expected fields in completed scan
        assert "attack_tree" in final_status or "results" in final_status
        print(f"SUCCESS: Scan completed - status={final_status['status']}, progress={final_status['progress']}%")
    
    def test_scan_history(self):
        """GET /api/scan/history - Returns scan history"""
        response = requests.get(f"{BASE_URL}/api/scan/history")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"SUCCESS: Scan history - {len(data)} scans in history")


class TestAttackChains:
    """Attack chains listing and details tests"""
    
    def test_get_chains(self):
        """GET /api/chains - Returns 6 attack chains"""
        response = requests.get(f"{BASE_URL}/api/chains")
        assert response.status_code == 200
        data = response.json()
        assert "chains" in data
        chains = data["chains"]
        
        # Should have 6 chains
        assert len(chains) == 6
        
        # Check chain structure
        for chain in chains:
            assert "id" in chain
            assert "name" in chain
            assert "description" in chain
            assert "steps_count" in chain or "total_steps" in chain
        
        print(f"SUCCESS: Chains - {len(chains)} attack chains returned")
        return chains
    
    def test_get_chain_details(self):
        """GET /api/chains/{chain_id} - Returns chain details with steps"""
        # Get chains first
        chains = requests.get(f"{BASE_URL}/api/chains").json()["chains"]
        chain_id = chains[0]["id"]
        
        response = requests.get(f"{BASE_URL}/api/chains/{chain_id}")
        assert response.status_code == 200
        data = response.json()
        
        assert "name" in data
        assert "steps" in data
        assert len(data["steps"]) > 0
        
        # Check step structure
        for step in data["steps"]:
            assert "id" in step
            assert "name" in step
            assert "actions" in step
        
        print(f"SUCCESS: Chain details - {data['name']} with {len(data['steps'])} steps")


class TestC2Dashboard:
    """C2 (Command & Control) dashboard tests"""
    
    def test_c2_dashboard(self):
        """GET /api/c2/dashboard - Returns MSF and Sliver status"""
        response = requests.get(f"{BASE_URL}/api/c2/dashboard")
        assert response.status_code == 200
        data = response.json()
        
        # Should have metasploit and sliver sections
        assert "metasploit" in data
        assert "sliver" in data
        
        # Check MSF structure
        msf = data["metasploit"]
        assert "connected" in msf
        # In preview, MSF should be offline
        print(f"MSF Status: connected={msf.get('connected')}")
        
        # Check Sliver structure
        sliver = data["sliver"]
        assert "connected" in sliver
        # In preview, Sliver should be offline
        print(f"Sliver Status: connected={sliver.get('connected')}")
        
        print(f"SUCCESS: C2 Dashboard - MSF={msf.get('connected')}, Sliver={sliver.get('connected')}")
    
    def test_msf_status(self):
        """GET /api/msf/status - Returns MSF RPC status"""
        response = requests.get(f"{BASE_URL}/api/msf/status")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data
        print(f"SUCCESS: MSF status - connected={data.get('connected')}")
    
    def test_sliver_status(self):
        """GET /api/sliver/status - Returns Sliver C2 status"""
        response = requests.get(f"{BASE_URL}/api/sliver/status")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data
        print(f"SUCCESS: Sliver status - connected={data.get('connected')}")


class TestMetasploitModules:
    """Metasploit modules listing tests"""
    
    def test_get_modules(self):
        """GET /api/metasploit/modules - Returns MSF modules list"""
        response = requests.get(f"{BASE_URL}/api/metasploit/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        modules = data["modules"]
        
        assert len(modules) > 0
        
        # Check module structure
        for mod in modules[:5]:
            assert "name" in mod
            assert "desc" in mod or "description" in mod
        
        print(f"SUCCESS: MSF modules - {len(modules)} modules returned")


class TestTools:
    """Red team tools listing tests"""
    
    def test_get_tools(self):
        """GET /api/tools - Returns red team tools"""
        response = requests.get(f"{BASE_URL}/api/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        tools = data["tools"]
        
        assert len(tools) > 0
        
        # Check for expected tools
        tool_names = [t.get("id") or t.get("name") for t in tools] if isinstance(tools, list) else list(tools.keys())
        expected_tools = ["nmap", "nikto", "gobuster"]
        for tool in expected_tools:
            assert tool in tool_names or any(tool in str(t) for t in tool_names), f"Missing tool: {tool}"
        
        print(f"SUCCESS: Tools - {len(tools)} tools returned")


class TestTacticalEngine:
    """Tactical decision engine tests"""
    
    def test_service_attacks(self):
        """GET /api/tactical/service-attacks - Returns service attack strategies"""
        response = requests.get(f"{BASE_URL}/api/tactical/service-attacks")
        assert response.status_code == 200
        data = response.json()
        
        # Data may be nested under 'strategies' key
        strategies = data.get("strategies", data)
        
        # Should have service attack mappings
        assert len(strategies) > 0
        
        # Check for common services
        expected_services = ["ssh", "http", "smb"]
        for svc in expected_services:
            assert svc in strategies, f"Missing service: {svc}"
        
        print(f"SUCCESS: Service attacks - {len(strategies)} services mapped")
    
    def test_vuln_exploits(self):
        """GET /api/tactical/vuln-exploits - Returns vulnerability exploit mappings"""
        response = requests.get(f"{BASE_URL}/api/tactical/vuln-exploits")
        assert response.status_code == 200
        data = response.json()
        
        # Data may be nested under 'mappings' key
        mappings = data.get("mappings", data)
        
        # Should have vulnerability mappings
        assert len(mappings) > 0
        
        # Check for common vulns
        expected_vulns = ["sql injection", "xss", "lfi"]
        for vuln in expected_vulns:
            assert vuln in mappings, f"Missing vuln: {vuln}"
        
        print(f"SUCCESS: Vuln exploits - {len(mappings)} vulnerabilities mapped")


class TestScanAbort:
    """Scan abort functionality test"""
    
    def test_abort_scan(self):
        """POST /api/scan/{id}/abort - Aborts running scan"""
        # Start a scan
        payload = {
            "target": "abort-test.example.com",
            "scan_phases": ["reconnaissance", "initial_access"],
            "tools": []
        }
        start_response = requests.post(f"{BASE_URL}/api/scan/start", json=payload)
        scan_id = start_response.json()["scan_id"]
        
        # Wait a moment for scan to start
        time.sleep(1)
        
        # Abort the scan
        response = requests.post(f"{BASE_URL}/api/scan/{scan_id}/abort")
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "aborted" or "abort" in str(data).lower()
        
        print(f"SUCCESS: Scan aborted - scan_id={scan_id}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
