"""
Test Docker Deployment Preparation - Iteration 13
Tests for Docker files validation and API endpoints for Docker deployment
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestDockerFilesExist:
    """Verify all Docker deployment files exist"""
    
    def test_docker_compose_exists(self):
        """docker-compose.yml exists"""
        assert os.path.exists('/app/docker-compose.yml'), "docker-compose.yml not found"
        with open('/app/docker-compose.yml', 'r') as f:
            content = f.read()
            assert 'services:' in content, "docker-compose.yml missing services section"
            assert 'mongo:' in content, "docker-compose.yml missing mongo service"
            assert 'backend:' in content, "docker-compose.yml missing backend service"
            assert 'frontend:' in content, "docker-compose.yml missing frontend service"
        print("PASS: docker-compose.yml exists with 3 services (mongo, backend, frontend)")
    
    def test_backend_dockerfile_exists(self):
        """backend/Dockerfile exists with correct content"""
        assert os.path.exists('/app/backend/Dockerfile'), "backend/Dockerfile not found"
        with open('/app/backend/Dockerfile', 'r') as f:
            content = f.read()
            assert 'python:3.11' in content, "Dockerfile missing Python 3.11 base image"
            assert 'nmap' in content, "Dockerfile missing nmap installation"
            assert 'nikto' in content, "Dockerfile missing nikto installation"
            assert 'uvicorn' in content, "Dockerfile missing uvicorn command"
        print("PASS: backend/Dockerfile exists with Python 3.11 + nmap + nikto")
    
    def test_backend_requirements_docker_exists(self):
        """backend/requirements.docker.txt exists"""
        assert os.path.exists('/app/backend/requirements.docker.txt'), "requirements.docker.txt not found"
        with open('/app/backend/requirements.docker.txt', 'r') as f:
            content = f.read()
            assert 'fastapi' in content, "requirements.docker.txt missing fastapi"
            assert 'motor' in content, "requirements.docker.txt missing motor"
            assert 'pymetasploit3' in content, "requirements.docker.txt missing pymetasploit3"
        print("PASS: backend/requirements.docker.txt exists with required packages")
    
    def test_frontend_dockerfile_exists(self):
        """frontend/Dockerfile exists with multi-stage build"""
        assert os.path.exists('/app/frontend/Dockerfile'), "frontend/Dockerfile not found"
        with open('/app/frontend/Dockerfile', 'r') as f:
            content = f.read()
            assert 'node:18' in content, "Dockerfile missing Node 18 base image"
            assert 'nginx' in content, "Dockerfile missing nginx stage"
            assert 'yarn build' in content, "Dockerfile missing yarn build command"
        print("PASS: frontend/Dockerfile exists with multi-stage React + Nginx build")
    
    def test_nginx_conf_exists(self):
        """frontend/nginx.conf exists with API proxy"""
        assert os.path.exists('/app/frontend/nginx.conf'), "nginx.conf not found"
        with open('/app/frontend/nginx.conf', 'r') as f:
            content = f.read()
            assert 'location /api/' in content, "nginx.conf missing /api/ proxy"
            assert 'proxy_pass http://backend:8001' in content, "nginx.conf missing backend proxy"
            assert 'Upgrade' in content, "nginx.conf missing WebSocket support"
        print("PASS: frontend/nginx.conf exists with /api/ proxy and WebSocket support")
    
    def test_env_docker_exists(self):
        """.env.docker template exists"""
        assert os.path.exists('/app/.env.docker'), ".env.docker not found"
        with open('/app/.env.docker', 'r') as f:
            content = f.read()
            assert 'LISTENER_IP' in content, ".env.docker missing LISTENER_IP"
            assert 'LISTENER_PORT' in content, ".env.docker missing LISTENER_PORT"
            assert 'MSF_RPC_HOST' in content, ".env.docker missing MSF_RPC_HOST"
            assert 'host.docker.internal' in content, ".env.docker missing host.docker.internal"
        print("PASS: .env.docker exists with LISTENER_IP, LISTENER_PORT, MSF_RPC_HOST")
    
    def test_docker_deploy_md_exists(self):
        """DOCKER_DEPLOY.md documentation exists"""
        assert os.path.exists('/app/DOCKER_DEPLOY.md'), "DOCKER_DEPLOY.md not found"
        with open('/app/DOCKER_DEPLOY.md', 'r') as f:
            content = f.read()
            assert 'docker compose' in content.lower(), "DOCKER_DEPLOY.md missing docker compose instructions"
            assert 'msfrpcd' in content.lower(), "DOCKER_DEPLOY.md missing msfrpcd instructions"
        print("PASS: DOCKER_DEPLOY.md exists with deployment documentation")


class TestHealthEndpoint:
    """Test /api/health endpoint for Docker deployment"""
    
    def test_health_returns_200(self):
        """GET /api/health returns 200"""
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print(f"PASS: GET /api/health returns 200")
    
    def test_health_mongodb_connected(self):
        """Health check shows MongoDB connected"""
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        data = response.json()
        assert "checks" in data, "Missing 'checks' in health response"
        assert "mongodb" in data["checks"], "Missing 'mongodb' in health checks"
        assert data["checks"]["mongodb"]["status"] == "connected", f"MongoDB not connected: {data['checks']['mongodb']}"
        print(f"PASS: MongoDB connected - {data['checks']['mongodb']}")
    
    def test_health_msf_rpc_status(self):
        """Health check shows MSF RPC status"""
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        data = response.json()
        assert "msf_rpc" in data["checks"], "Missing 'msf_rpc' in health checks"
        msf = data["checks"]["msf_rpc"]
        assert "host" in msf, "Missing 'host' in msf_rpc"
        assert "port" in msf, "Missing 'port' in msf_rpc"
        assert "token_set" in msf, "Missing 'token_set' in msf_rpc"
        assert "connected" in msf, "Missing 'connected' in msf_rpc"
        print(f"PASS: MSF RPC status - host={msf['host']}, port={msf['port']}, token_set={msf['token_set']}, connected={msf['connected']}")
    
    def test_health_sliver_status(self):
        """Health check shows Sliver status"""
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        data = response.json()
        assert "sliver" in data["checks"], "Missing 'sliver' in health checks"
        sliver = data["checks"]["sliver"]
        assert "config_path" in sliver, "Missing 'config_path' in sliver"
        assert "connected" in sliver, "Missing 'connected' in sliver"
        print(f"PASS: Sliver status - config_path={sliver['config_path']}, connected={sliver['connected']}")
    
    def test_health_listener_status(self):
        """Health check shows listener config"""
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        data = response.json()
        assert "listener" in data["checks"], "Missing 'listener' in health checks"
        listener = data["checks"]["listener"]
        assert "ip" in listener, "Missing 'ip' in listener"
        assert "port" in listener, "Missing 'port' in listener"
        assert "configured" in listener, "Missing 'configured' in listener"
        print(f"PASS: Listener status - ip={listener['ip']}, port={listener['port']}, configured={listener['configured']}")


class TestRootEndpoint:
    """Test /api/ root endpoint"""
    
    def test_root_returns_version(self):
        """GET /api/ returns version 5.0.0"""
        response = requests.get(f"{BASE_URL}/api/", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "version" in data, "Missing 'version' in response"
        assert data["version"] == "5.0.0", f"Expected version 5.0.0, got {data['version']}"
        print(f"PASS: GET /api/ returns version {data['version']}")
    
    def test_root_has_docker_feature(self):
        """GET /api/ features list includes 'docker'"""
        response = requests.get(f"{BASE_URL}/api/", timeout=10)
        data = response.json()
        assert "features" in data, "Missing 'features' in response"
        assert "docker" in data["features"], f"'docker' not in features: {data['features']}"
        print(f"PASS: Features include 'docker': {data['features']}")


class TestConfigEndpoint:
    """Test /api/config endpoint"""
    
    def test_config_returns_listener(self):
        """GET /api/config returns listener config"""
        response = requests.get(f"{BASE_URL}/api/config", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "listener_ip" in data, "Missing 'listener_ip' in config"
        assert "listener_port" in data, "Missing 'listener_port' in config"
        print(f"PASS: GET /api/config returns listener_ip={data['listener_ip']}, listener_port={data['listener_port']}")
    
    def test_config_update_persists(self):
        """PUT /api/config updates and persists config"""
        # Get current config
        response = requests.get(f"{BASE_URL}/api/config", timeout=10)
        original = response.json()
        
        # Update config
        new_config = {
            "listener_ip": "10.10.14.99",
            "listener_port": 5555
        }
        response = requests.put(f"{BASE_URL}/api/config", json=new_config, timeout=10)
        assert response.status_code == 200, f"PUT failed: {response.status_code}"
        
        # Verify update
        response = requests.get(f"{BASE_URL}/api/config", timeout=10)
        data = response.json()
        assert data["listener_ip"] == "10.10.14.99", f"listener_ip not updated: {data['listener_ip']}"
        assert data["listener_port"] == 5555, f"listener_port not updated: {data['listener_port']}"
        
        # Restore original
        requests.put(f"{BASE_URL}/api/config", json=original, timeout=10)
        print(f"PASS: PUT /api/config updates and persists config")


class TestPayloadsEndpoint:
    """Test /api/payloads/templates endpoint"""
    
    def test_payloads_templates_returns_11(self):
        """GET /api/payloads/templates returns 11 payloads"""
        response = requests.get(f"{BASE_URL}/api/payloads/templates", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "payloads" in data, "Missing 'payloads' in response"
        assert len(data["payloads"]) == 11, f"Expected 11 payloads, got {len(data['payloads'])}"
        print(f"PASS: GET /api/payloads/templates returns {len(data['payloads'])} payloads")
    
    def test_payload_generate_injects_lhost(self):
        """POST /api/payloads/generate returns payload with LHOST injected"""
        # First set a listener IP
        requests.put(f"{BASE_URL}/api/config", json={"listener_ip": "10.10.14.5", "listener_port": 4444}, timeout=10)
        
        # Generate payload using correct payload_id (from templates list)
        response = requests.post(f"{BASE_URL}/api/payloads/generate", json={
            "payload_id": "windows/meterpreter/reverse_tcp"
        }, timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "generator_cmd" in data or "lhost" in data, f"Missing 'generator_cmd' or 'lhost' in response: {data}"
        # Check LHOST is injected
        payload_str = str(data)
        assert "10.10.14.5" in payload_str, f"LHOST not injected in payload: {data}"
        print(f"PASS: POST /api/payloads/generate returns payload with LHOST={data.get('lhost')}")


class TestC2Dashboard:
    """Test /api/c2/dashboard endpoint"""
    
    def test_c2_dashboard_returns_both_statuses(self):
        """GET /api/c2/dashboard returns MSF and Sliver status"""
        response = requests.get(f"{BASE_URL}/api/c2/dashboard", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "metasploit" in data, "Missing 'metasploit' in dashboard"
        assert "sliver" in data, "Missing 'sliver' in dashboard"
        print(f"PASS: GET /api/c2/dashboard returns metasploit and sliver status")
    
    def test_c2_dashboard_has_diagnostics(self):
        """GET /api/c2/dashboard includes diagnostics"""
        response = requests.get(f"{BASE_URL}/api/c2/dashboard", timeout=10)
        data = response.json()
        msf = data.get("metasploit", {})
        # Check for diagnostics fields
        assert "diagnostics" in msf or "token_set" in msf or "port_reachable" in msf, f"Missing diagnostics in metasploit: {msf}"
        print(f"PASS: GET /api/c2/dashboard includes diagnostics")


class TestScanEndpoints:
    """Test scan endpoints"""
    
    def test_scan_start_returns_scan_id(self):
        """POST /api/scan/start returns scan_id"""
        response = requests.post(f"{BASE_URL}/api/scan/start", json={
            "target": "127.0.0.1",
            "scan_phases": ["reconnaissance"]
        }, timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "scan_id" in data, "Missing 'scan_id' in response"
        print(f"PASS: POST /api/scan/start returns scan_id={data['scan_id']}")
        return data["scan_id"]
    
    def test_scan_status_returns_completed(self):
        """GET /api/scan/{id}/status returns completed after ~8 seconds"""
        import time
        # Start scan
        response = requests.post(f"{BASE_URL}/api/scan/start", json={
            "target": "127.0.0.1",
            "scan_phases": ["reconnaissance"]
        }, timeout=10)
        scan_id = response.json()["scan_id"]
        
        # Poll for completion
        for i in range(10):
            time.sleep(1)
            response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status", timeout=10)
            data = response.json()
            if data.get("status") == "completed":
                print(f"PASS: Scan completed after {i+1} seconds")
                return
        
        # Check final status
        assert data.get("status") == "completed", f"Scan not completed after 10s: {data.get('status')}"


class TestChainsEndpoint:
    """Test /api/chains endpoint"""
    
    def test_chains_returns_6(self):
        """GET /api/chains returns 6 chains"""
        response = requests.get(f"{BASE_URL}/api/chains", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "chains" in data, "Missing 'chains' in response"
        assert len(data["chains"]) == 6, f"Expected 6 chains, got {len(data['chains'])}"
        print(f"PASS: GET /api/chains returns {len(data['chains'])} chains")


class TestMitreEndpoint:
    """Test /api/mitre/tactics endpoint"""
    
    def test_mitre_tactics_returns_data(self):
        """GET /api/mitre/tactics returns tactics"""
        response = requests.get(f"{BASE_URL}/api/mitre/tactics", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "tactics" in data, "Missing 'tactics' in response"
        assert len(data["tactics"]) > 0, "No tactics returned"
        print(f"PASS: GET /api/mitre/tactics returns {len(data['tactics'])} tactics")


class TestMsfDiagnostics:
    """Test /api/msf/diagnostics endpoint"""
    
    def test_msf_diagnostics_returns_connection_info(self):
        """GET /api/msf/diagnostics returns connection diagnostics"""
        response = requests.get(f"{BASE_URL}/api/msf/diagnostics", timeout=10)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        # Check for diagnostic fields
        assert "host" in data or "diagnostics" in data, f"Missing diagnostic info: {data}"
        print(f"PASS: GET /api/msf/diagnostics returns connection info")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
