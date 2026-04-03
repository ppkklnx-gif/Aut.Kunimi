"""
Backend API Tests for Red Team Automation Framework v3.1
Focus: Attack Chains Feature Testing

Tests cover:
- GET /api/ - Health check
- GET /api/chains - List all attack chains
- GET /api/chains/{chain_id} - Get chain details
- POST /api/chains/{chain_id}/generate - Generate chain commands
- POST /api/chains/detect - Detect applicable chains
- POST /api/chains/execute - Execute chain
- GET /api/chains/execution/{id} - Get execution status
- Other core endpoints (MITRE, tools, MSF, tactical)
"""

import pytest
import requests
import os
import uuid

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestHealthCheck:
    """Health check and framework info tests"""
    
    def test_api_health_check(self):
        """GET /api/ - returns framework info"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Red Team" in data["message"]
        assert "version" in data
        assert "features" in data
        print(f"✓ Health check passed: {data['message']} v{data['version']}")


class TestAttackChains:
    """Attack Chains API tests - Core feature"""
    
    def test_get_all_chains(self):
        """GET /api/chains - returns all 6 attack chains"""
        response = requests.get(f"{BASE_URL}/api/chains")
        assert response.status_code == 200
        data = response.json()
        assert "chains" in data
        chains = data["chains"]
        assert len(chains) == 6, f"Expected 6 chains, got {len(chains)}"
        
        # Verify chain structure
        for chain in chains:
            assert "id" in chain
            assert "name" in chain
            assert "description" in chain
            assert "triggers" in chain
            assert "steps_count" in chain
            assert isinstance(chain["triggers"], list)
            assert chain["steps_count"] > 0
        
        # Verify expected chain IDs
        chain_ids = [c["id"] for c in chains]
        expected_ids = ["web_to_shell", "smb_to_domain", "kerberos_attack", 
                       "linux_privesc", "windows_privesc", "phishing_to_shell"]
        for expected_id in expected_ids:
            assert expected_id in chain_ids, f"Missing chain: {expected_id}"
        
        print(f"✓ All 6 attack chains returned: {chain_ids}")
    
    def test_get_web_to_shell_chain(self):
        """GET /api/chains/web_to_shell - returns full chain details"""
        response = requests.get(f"{BASE_URL}/api/chains/web_to_shell")
        assert response.status_code == 200
        data = response.json()
        
        assert "name" in data
        assert data["name"] == "Web App to Shell"
        assert "description" in data
        assert "trigger" in data
        assert "steps" in data
        assert len(data["steps"]) == 4  # 4 steps in web_to_shell
        
        # Verify step structure
        for step in data["steps"]:
            assert "id" in step
            assert "name" in step
            assert "actions" in step
            assert len(step["actions"]) > 0
        
        print(f"✓ web_to_shell chain: {data['name']} with {len(data['steps'])} steps")
    
    def test_get_smb_to_domain_chain(self):
        """GET /api/chains/smb_to_domain - returns SMB chain details"""
        response = requests.get(f"{BASE_URL}/api/chains/smb_to_domain")
        assert response.status_code == 200
        data = response.json()
        
        assert data["name"] == "SMB to Domain Admin"
        assert "steps" in data
        assert len(data["steps"]) == 4
        print(f"✓ smb_to_domain chain: {data['name']} with {len(data['steps'])} steps")
    
    def test_get_kerberos_attack_chain(self):
        """GET /api/chains/kerberos_attack - returns Kerberos chain details"""
        response = requests.get(f"{BASE_URL}/api/chains/kerberos_attack")
        assert response.status_code == 200
        data = response.json()
        
        assert data["name"] == "Kerberos Attack Chain"
        assert "steps" in data
        assert len(data["steps"]) == 5  # 5 steps in kerberos_attack
        print(f"✓ kerberos_attack chain: {data['name']} with {len(data['steps'])} steps")
    
    def test_get_nonexistent_chain(self):
        """GET /api/chains/nonexistent - returns 404"""
        response = requests.get(f"{BASE_URL}/api/chains/nonexistent")
        assert response.status_code == 404
        print("✓ Nonexistent chain returns 404")
    
    def test_generate_chain_commands(self):
        """POST /api/chains/web_to_shell/generate - generates commands with context"""
        context = {
            "target": "10.10.10.1",
            "url": "http://10.10.10.1/vuln",
            "lhost": "10.10.14.1"
        }
        response = requests.post(f"{BASE_URL}/api/chains/web_to_shell/generate", json=context)
        assert response.status_code == 200
        data = response.json()
        
        assert "chain_id" in data
        assert data["chain_id"] == "web_to_shell"
        assert "commands" in data
        assert len(data["commands"]) > 0
        
        # Verify command structure
        for cmd in data["commands"]:
            assert "step_id" in cmd
            assert "step_name" in cmd
            assert "commands" in cmd
        
        # Verify context variables were substituted
        commands_str = str(data["commands"])
        assert "10.10.10.1" in commands_str or "{target}" not in commands_str
        
        print(f"✓ Generated {len(data['commands'])} steps with commands")
    
    def test_detect_applicable_chains_smb(self):
        """POST /api/chains/detect - detects SMB chain from findings"""
        findings = {
            "ports": ["445/tcp"],
            "services": ["smb"]
        }
        response = requests.post(f"{BASE_URL}/api/chains/detect", json=findings)
        assert response.status_code == 200
        data = response.json()
        
        assert "applicable_chains" in data
        assert "count" in data
        assert data["count"] > 0
        
        # SMB findings should trigger smb_to_domain chain
        chain_ids = [c["id"] for c in data["applicable_chains"]]
        assert "smb_to_domain" in chain_ids, f"SMB chain not detected. Found: {chain_ids}"
        
        print(f"✓ Detected {data['count']} applicable chains for SMB findings")
    
    def test_detect_applicable_chains_kerberos(self):
        """POST /api/chains/detect - detects Kerberos chain"""
        findings = {
            "ports": ["88/tcp"],
            "services": ["kerberos"]
        }
        response = requests.post(f"{BASE_URL}/api/chains/detect", json=findings)
        assert response.status_code == 200
        data = response.json()
        
        chain_ids = [c["id"] for c in data["applicable_chains"]]
        assert "kerberos_attack" in chain_ids
        print(f"✓ Detected Kerberos chain from findings")
    
    def test_execute_chain(self):
        """POST /api/chains/execute - creates chain execution"""
        payload = {
            "scan_id": "",
            "chain_id": "web_to_shell",
            "target": "10.10.10.1",
            "context": {"lhost": "10.10.14.1"},
            "auto_execute": False
        }
        response = requests.post(f"{BASE_URL}/api/chains/execute", json=payload)
        assert response.status_code == 200
        data = response.json()
        
        assert "execution_id" in data
        assert "chain_id" in data
        assert data["chain_id"] == "web_to_shell"
        assert "chain_name" in data
        assert "status" in data
        assert "commands" in data
        
        # Store execution_id for next test
        TestAttackChains.execution_id = data["execution_id"]
        print(f"✓ Chain execution created: {data['execution_id']}")
    
    def test_get_chain_execution_status(self):
        """GET /api/chains/execution/{id} - returns execution status"""
        execution_id = getattr(TestAttackChains, 'execution_id', None)
        if not execution_id:
            pytest.skip("No execution_id from previous test")
        
        response = requests.get(f"{BASE_URL}/api/chains/execution/{execution_id}")
        assert response.status_code == 200
        data = response.json()
        
        assert "id" in data
        assert data["id"] == execution_id
        assert "status" in data
        assert "chain_id" in data
        print(f"✓ Execution status: {data['status']}")
    
    def test_get_nonexistent_execution(self):
        """GET /api/chains/execution/nonexistent - returns 404"""
        response = requests.get(f"{BASE_URL}/api/chains/execution/nonexistent-id-12345")
        assert response.status_code == 404
        print("✓ Nonexistent execution returns 404")


class TestMITREAndTools:
    """MITRE ATT&CK and Tools API tests"""
    
    def test_get_mitre_tactics(self):
        """GET /api/mitre/tactics - returns MITRE tactics"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics")
        assert response.status_code == 200
        data = response.json()
        
        assert "tactics" in data
        tactics = data["tactics"]
        assert len(tactics) >= 14  # 14 MITRE tactics
        
        # Verify key tactics exist
        assert "reconnaissance" in tactics
        assert "initial_access" in tactics
        assert "execution" in tactics
        print(f"✓ MITRE tactics: {len(tactics)} tactics returned")
    
    def test_get_tools(self):
        """GET /api/tools - returns tools list"""
        response = requests.get(f"{BASE_URL}/api/tools")
        assert response.status_code == 200
        data = response.json()
        
        assert "tools" in data
        tools = data["tools"]
        assert len(tools) > 0
        
        # Verify tool structure
        for tool_id, tool_info in tools.items():
            assert "phase" in tool_info
            assert "cmd" in tool_info
        
        print(f"✓ Tools: {len(tools)} tools returned")
    
    def test_get_metasploit_modules(self):
        """GET /api/metasploit/modules - returns MSF modules"""
        response = requests.get(f"{BASE_URL}/api/metasploit/modules")
        assert response.status_code == 200
        data = response.json()
        
        assert "modules" in data
        modules = data["modules"]
        assert len(modules) > 0
        
        # Verify module structure
        for mod in modules:
            assert "name" in mod
            assert "desc" in mod
            assert "rank" in mod
            assert "category" in mod
        
        print(f"✓ Metasploit modules: {len(modules)} modules returned")


class TestTacticalEngine:
    """Tactical Decision Engine API tests"""
    
    def test_get_service_attacks(self):
        """GET /api/tactical/service-attacks - returns service attack strategies"""
        response = requests.get(f"{BASE_URL}/api/tactical/service-attacks")
        assert response.status_code == 200
        data = response.json()
        
        assert "strategies" in data
        strategies = data["strategies"]
        
        # Verify key services
        assert "ssh" in strategies
        assert "http" in strategies
        assert "smb" in strategies
        assert "rdp" in strategies
        
        print(f"✓ Service attacks: {len(strategies)} strategies returned")
    
    def test_get_waf_bypass_cloudflare(self):
        """GET /api/tactical/waf-bypass/cloudflare - returns cloudflare bypass"""
        response = requests.get(f"{BASE_URL}/api/tactical/waf-bypass/cloudflare")
        assert response.status_code == 200
        data = response.json()
        
        assert "name" in data
        assert "techniques" in data
        assert len(data["techniques"]) > 0
        
        print(f"✓ Cloudflare WAF bypass: {len(data['techniques'])} techniques")
    
    def test_get_waf_bypass_default(self):
        """GET /api/tactical/waf-bypass/unknown - returns default strategy"""
        response = requests.get(f"{BASE_URL}/api/tactical/waf-bypass/unknown_waf")
        assert response.status_code == 200
        data = response.json()
        
        assert "name" in data
        assert data["name"] == "Generic WAF"
        print("✓ Unknown WAF returns default strategy")


class TestScanHistory:
    """Scan history API tests"""
    
    def test_get_scan_history(self):
        """GET /api/scan/history - returns scan history array"""
        response = requests.get(f"{BASE_URL}/api/scan/history")
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        print(f"✓ Scan history: {len(data)} scans in history")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
