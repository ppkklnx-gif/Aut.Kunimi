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

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Kimi API configuration
KIMI_API_KEY = os.environ.get('KIMI_API_KEY', '')
KIMI_API_URL = "https://api.moonshot.ai/v1/chat/completions"

# Create the main app
app = FastAPI(title="Kali Pentesting Automation Suite")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory scan progress tracking
scan_progress: Dict[str, Dict[str, Any]] = {}

# Attack tree storage
attack_trees: Dict[str, Dict[str, Any]] = {}

# Models
class ScanCreate(BaseModel):
    target: str
    scan_types: List[str] = ["waf", "nmap", "nikto"]

class ScanStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    target: str
    status: str
    current_tool: Optional[str] = None
    progress: int = 0
    results: Dict[str, Any] = {}
    ai_analysis: Optional[str] = None
    exploit_suggestions: List[Dict[str, Any]] = []
    created_at: str
    updated_at: str

class ScanHistoryItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    target: str
    status: str
    tools_used: List[str]
    vulnerabilities_found: int
    created_at: str

class AIAnalysisRequest(BaseModel):
    scan_id: str
    results: Dict[str, Any]

class MetasploitExploit(BaseModel):
    scan_id: str
    node_id: str
    module: str
    target_host: str
    target_port: Optional[int] = None
    options: Dict[str, str] = {}

class AttackNode(BaseModel):
    id: str
    parent_id: Optional[str] = None
    type: str  # "target", "service", "vulnerability", "exploit", "access"
    name: str
    description: str
    status: str = "pending"  # "pending", "testing", "success", "failed", "verified"
    severity: Optional[str] = None  # "critical", "high", "medium", "low", "info"
    data: Dict[str, Any] = {}
    children: List[str] = []

class UpdateNodeStatus(BaseModel):
    status: str
    notes: Optional[str] = None

# Helper functions
def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse nmap output to extract ports and services"""
    ports = []
    lines = output.split('\n')
    for line in lines:
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                ports.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2] if len(parts) > 2 else "unknown"
                })
    return {"ports": ports, "raw": output}

def parse_waf_output(output: str) -> Dict[str, Any]:
    """Parse wafw00f output"""
    waf_detected = None
    if "is behind" in output.lower():
        match = re.search(r'is behind (.+?)(?:\n|$)', output, re.IGNORECASE)
        if match:
            waf_detected = match.group(1).strip()
    elif "no waf" in output.lower() or "no firewall" in output.lower():
        waf_detected = "None Detected"
    return {"waf": waf_detected, "raw": output}

def parse_nikto_output(output: str) -> Dict[str, Any]:
    """Parse nikto output for vulnerabilities"""
    vulns = []
    lines = output.split('\n')
    for line in lines:
        if line.strip().startswith('+'):
            vulns.append(line.strip())
    return {"vulnerabilities": vulns, "raw": output}

async def run_tool(tool: str, target: str, scan_id: str) -> Dict[str, Any]:
    """Run a security tool and return results"""
    logger.info(f"Running {tool} on {target}")
    
    try:
        if tool == "waf":
            cmd = ["wafw00f", target, "-o", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return parse_waf_output(result.stdout + result.stderr)
            
        elif tool == "nmap":
            cmd = ["nmap", "-sV", "-sC", "--top-ports", "100", "-T4", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return parse_nmap_output(result.stdout)
            
        elif tool == "nikto":
            cmd = ["nikto", "-h", target, "-Format", "txt", "-timeout", "10"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return parse_nikto_output(result.stdout + result.stderr)
            
        elif tool == "whatweb":
            cmd = ["whatweb", "-v", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"fingerprint": result.stdout, "raw": result.stdout}
            
        elif tool == "subfinder":
            cmd = ["subfinder", "-d", target, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            return {"subdomains": subdomains, "count": len(subdomains)}
            
        elif tool == "sn1per":
            return {"status": "Sn1per requires manual execution", "note": "Run: sniper -t " + target}
            
        else:
            return {"error": f"Unknown tool: {tool}"}
            
    except subprocess.TimeoutExpired:
        return {"error": f"{tool} timed out", "raw": ""}
    except FileNotFoundError:
        return {"error": f"{tool} not found - please install it", "simulated": True, "raw": f"[SIMULATED] {tool} output for {target}"}
    except Exception as e:
        logger.error(f"Error running {tool}: {str(e)}")
        return {"error": str(e), "raw": ""}

async def run_metasploit_module(module: str, target: str, port: Optional[int], options: Dict[str, str]) -> Dict[str, Any]:
    """Execute a Metasploit module"""
    logger.info(f"Running Metasploit module: {module} against {target}")
    
    try:
        # Build msfconsole command
        rc_content = f"""
use {module}
set RHOSTS {target}
"""
        if port:
            rc_content += f"set RPORT {port}\n"
        
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        
        rc_content += "run\nexit\n"
        
        # Write RC file
        rc_file = f"/tmp/msf_{uuid.uuid4().hex[:8]}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        # Execute msfconsole
        cmd = ["msfconsole", "-q", "-r", rc_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Clean up
        os.remove(rc_file)
        
        # Parse output for success indicators
        output = result.stdout + result.stderr
        success = False
        session_opened = False
        
        if "session" in output.lower() and "opened" in output.lower():
            session_opened = True
            success = True
        elif "exploit completed" in output.lower():
            success = True
        elif "auxiliary module execution completed" in output.lower():
            success = True
        
        return {
            "module": module,
            "target": target,
            "port": port,
            "success": success,
            "session_opened": session_opened,
            "output": output,
            "rc_command": rc_content
        }
        
    except subprocess.TimeoutExpired:
        return {"error": "Metasploit timed out", "module": module}
    except FileNotFoundError:
        # Simulate if msfconsole not available
        return {
            "module": module,
            "target": target,
            "port": port,
            "success": False,
            "simulated": True,
            "output": f"[SIMULATED] Metasploit execution for {module}",
            "rc_command": f"use {module}\nset RHOSTS {target}\nrun"
        }
    except Exception as e:
        logger.error(f"Error running Metasploit: {str(e)}")
        return {"error": str(e), "module": module}

async def analyze_with_kimi(results: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Send results to Kimi K2 for AI analysis"""
    if not KIMI_API_KEY:
        return {
            "analysis": "Kimi API key not configured. Please add KIMI_API_KEY to your environment.",
            "exploits": [],
            "attack_paths": []
        }
    
    prompt = f"""Eres un experto en ciberseguridad y pentesting. Analiza los siguientes resultados de escaneo para el objetivo: {target}

RESULTADOS DEL ESCANEO:
{json.dumps(results, indent=2, default=str)}

Por favor proporciona un análisis estructurado:

1. RESUMEN DE HALLAZGOS: Lista de vulnerabilidades encontradas ordenadas por severidad (Crítica, Alta, Media, Baja)

2. ÁRBOL DE ATAQUE: Para cada vulnerabilidad, describe la ruta de explotación como un camino:
   - Servicio afectado → Vulnerabilidad → Exploit recomendado → Posible acceso obtenido
   Formato JSON para cada ruta:
   {{"service": "nombre", "vuln": "CVE o descripción", "exploit": "módulo metasploit", "access": "tipo de acceso"}}

3. COMANDOS METASPLOIT: Para cada vulnerabilidad explotable, proporciona el comando completo:
   ```
   use exploit/...
   set RHOSTS {target}
   set RPORT puerto
   run
   ```

4. COMANDOS SQLMAP: Si hay indicios de SQL Injection:
   ```
   sqlmap -u "URL" --dbs
   ```

5. PRIORIDAD DE EXPLOTACIÓN: Ordena las vulnerabilidades por facilidad de explotación y impacto

6. RECOMENDACIONES: Próximos pasos para continuar la auditoría

Responde en español. Sé muy específico con los módulos de Metasploit y comandos."""

    try:
        async with httpx.AsyncClient(timeout=90.0) as http_client:
            response = await http_client.post(
                KIMI_API_URL,
                headers={
                    "Authorization": f"Bearer {KIMI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "kimi-k2-0711-preview",
                    "messages": [
                        {"role": "system", "content": "Eres un experto pentester con conocimiento profundo de Metasploit, Kali Linux, y explotación de vulnerabilidades. Siempre proporcionas comandos específicos y ejecutables."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.5,
                    "max_tokens": 6000
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                ai_response = data["choices"][0]["message"]["content"]
                
                # Extract exploit suggestions
                exploits = []
                attack_paths = []
                
                lines = ai_response.split('\n')
                current_exploit = None
                
                for line in lines:
                    line_lower = line.lower().strip()
                    
                    # Parse Metasploit modules
                    if 'use ' in line_lower and ('exploit/' in line_lower or 'auxiliary/' in line_lower):
                        match = re.search(r'use\s+((?:exploit|auxiliary|post)/[^\s]+)', line, re.IGNORECASE)
                        if match:
                            current_exploit = {"type": "metasploit", "module": match.group(1), "commands": [line.strip()]}
                    elif current_exploit and ('set ' in line_lower or 'run' in line_lower or 'exploit' == line_lower):
                        current_exploit["commands"].append(line.strip())
                        if 'run' in line_lower or 'exploit' == line_lower:
                            exploits.append(current_exploit)
                            current_exploit = None
                    
                    # Parse SQLmap commands
                    if 'sqlmap' in line_lower:
                        exploits.append({"type": "sqlmap", "command": line.strip()})
                    
                    # Parse attack paths from JSON
                    if '{"service"' in line or "{'service'" in line:
                        try:
                            path_match = re.search(r'\{[^}]+\}', line)
                            if path_match:
                                path = json.loads(path_match.group().replace("'", '"'))
                                attack_paths.append(path)
                        except:
                            pass
                
                return {
                    "analysis": ai_response,
                    "exploits": exploits,
                    "attack_paths": attack_paths
                }
            else:
                return {
                    "analysis": f"Error de API Kimi: {response.status_code} - {response.text}",
                    "exploits": [],
                    "attack_paths": []
                }
                
    except Exception as e:
        logger.error(f"Error calling Kimi API: {str(e)}")
        return {
            "analysis": f"Error al conectar con Kimi: {str(e)}",
            "exploits": [],
            "attack_paths": []
        }

def build_attack_tree(scan_id: str, target: str, results: Dict[str, Any], ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build attack tree from scan results"""
    tree = {
        "scan_id": scan_id,
        "root": {
            "id": "root",
            "type": "target",
            "name": target,
            "description": f"Objetivo principal: {target}",
            "status": "testing",
            "children": []
        },
        "nodes": {}
    }
    
    node_id = 0
    
    # Add services from nmap
    if "nmap" in results and "ports" in results["nmap"]:
        for port_info in results["nmap"]["ports"]:
            node_id += 1
            service_node_id = f"service_{node_id}"
            service_node = {
                "id": service_node_id,
                "parent_id": "root",
                "type": "service",
                "name": f"{port_info['service']} ({port_info['port']})",
                "description": f"Puerto {port_info['port']} - Estado: {port_info['state']}",
                "status": "pending",
                "severity": "info",
                "data": port_info,
                "children": []
            }
            tree["nodes"][service_node_id] = service_node
            tree["root"]["children"].append(service_node_id)
    
    # Add vulnerabilities from nikto
    if "nikto" in results and "vulnerabilities" in results["nikto"]:
        for vuln in results["nikto"]["vulnerabilities"][:10]:  # Limit to 10
            node_id += 1
            vuln_node_id = f"vuln_{node_id}"
            
            # Determine severity based on keywords
            severity = "medium"
            vuln_lower = vuln.lower()
            if "critical" in vuln_lower or "rce" in vuln_lower or "remote code" in vuln_lower:
                severity = "critical"
            elif "sql" in vuln_lower or "injection" in vuln_lower or "xss" in vuln_lower:
                severity = "high"
            elif "disclosure" in vuln_lower or "info" in vuln_lower:
                severity = "low"
            
            vuln_node = {
                "id": vuln_node_id,
                "parent_id": "root",
                "type": "vulnerability",
                "name": vuln[:50] + "..." if len(vuln) > 50 else vuln,
                "description": vuln,
                "status": "pending",
                "severity": severity,
                "data": {"raw": vuln},
                "children": []
            }
            tree["nodes"][vuln_node_id] = vuln_node
            tree["root"]["children"].append(vuln_node_id)
    
    # Add WAF info
    if "waf" in results and results["waf"].get("waf"):
        node_id += 1
        waf_node_id = f"waf_{node_id}"
        waf_node = {
            "id": waf_node_id,
            "parent_id": "root",
            "type": "defense",
            "name": f"WAF: {results['waf']['waf']}",
            "description": f"Firewall detectado: {results['waf']['waf']}",
            "status": "verified",
            "severity": "info",
            "data": results["waf"],
            "children": []
        }
        tree["nodes"][waf_node_id] = waf_node
        tree["root"]["children"].append(waf_node_id)
    
    # Add subdomains
    if "subfinder" in results and "subdomains" in results["subfinder"]:
        for subdomain in results["subfinder"]["subdomains"][:5]:  # Limit to 5
            node_id += 1
            sub_node_id = f"subdomain_{node_id}"
            sub_node = {
                "id": sub_node_id,
                "parent_id": "root",
                "type": "subdomain",
                "name": subdomain,
                "description": f"Subdominio descubierto: {subdomain}",
                "status": "pending",
                "severity": "info",
                "data": {"subdomain": subdomain},
                "children": []
            }
            tree["nodes"][sub_node_id] = sub_node
            tree["root"]["children"].append(sub_node_id)
    
    # Add exploit suggestions from AI
    if "exploits" in ai_analysis:
        for exploit in ai_analysis["exploits"]:
            node_id += 1
            exploit_node_id = f"exploit_{node_id}"
            
            if exploit.get("type") == "metasploit":
                exploit_node = {
                    "id": exploit_node_id,
                    "parent_id": "root",
                    "type": "exploit",
                    "name": exploit.get("module", "Metasploit Module"),
                    "description": "\n".join(exploit.get("commands", [])),
                    "status": "pending",
                    "severity": "critical",
                    "data": exploit,
                    "children": []
                }
            else:
                exploit_node = {
                    "id": exploit_node_id,
                    "parent_id": "root",
                    "type": "exploit",
                    "name": exploit.get("type", "Exploit").upper(),
                    "description": exploit.get("command", ""),
                    "status": "pending",
                    "severity": "high",
                    "data": exploit,
                    "children": []
                }
            
            tree["nodes"][exploit_node_id] = exploit_node
            tree["root"]["children"].append(exploit_node_id)
    
    return tree

async def run_scan_background(scan_id: str, target: str, scan_types: List[str]):
    """Background task to run all scans"""
    global scan_progress, attack_trees
    
    scan_progress[scan_id] = {
        "status": "running",
        "current_tool": None,
        "progress": 0,
        "results": {},
        "ai_analysis": None,
        "exploit_suggestions": [],
        "attack_tree": None
    }
    
    total_tools = len(scan_types) + 1  # +1 for AI analysis
    completed = 0
    
    try:
        for tool in scan_types:
            scan_progress[scan_id]["current_tool"] = tool
            scan_progress[scan_id]["progress"] = int((completed / total_tools) * 100)
            
            result = await run_tool(tool, target, scan_id)
            scan_progress[scan_id]["results"][tool] = result
            completed += 1
            
        # AI Analysis
        scan_progress[scan_id]["current_tool"] = "kimi_ai"
        scan_progress[scan_id]["progress"] = int((completed / total_tools) * 100)
        
        ai_result = await analyze_with_kimi(scan_progress[scan_id]["results"], target)
        scan_progress[scan_id]["ai_analysis"] = ai_result["analysis"]
        scan_progress[scan_id]["exploit_suggestions"] = ai_result["exploits"]
        
        # Build attack tree
        attack_tree = build_attack_tree(scan_id, target, scan_progress[scan_id]["results"], ai_result)
        scan_progress[scan_id]["attack_tree"] = attack_tree
        attack_trees[scan_id] = attack_tree
        
        # Mark as completed
        scan_progress[scan_id]["status"] = "completed"
        scan_progress[scan_id]["progress"] = 100
        scan_progress[scan_id]["current_tool"] = None
        
        # Save to database
        scan_doc = {
            "id": scan_id,
            "target": target,
            "status": "completed",
            "tools_used": scan_types,
            "results": scan_progress[scan_id]["results"],
            "ai_analysis": scan_progress[scan_id]["ai_analysis"],
            "exploit_suggestions": scan_progress[scan_id]["exploit_suggestions"],
            "attack_tree": attack_tree,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        await db.scans.insert_one(scan_doc)
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        scan_progress[scan_id]["status"] = "error"
        scan_progress[scan_id]["error"] = str(e)

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Kali Pentesting Automation Suite API", "version": "2.0.0"}

@api_router.post("/scan/start")
async def start_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """Start a new penetration test scan"""
    scan_id = str(uuid.uuid4())
    
    target = scan.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    background_tasks.add_task(run_scan_background, scan_id, clean_target, scan.scan_types)
    
    return {
        "scan_id": scan_id,
        "target": clean_target,
        "status": "started",
        "tools": scan.scan_types
    }

@api_router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get current scan status and progress"""
    if scan_id in scan_progress:
        progress = scan_progress[scan_id]
        return {
            "scan_id": scan_id,
            "status": progress["status"],
            "current_tool": progress["current_tool"],
            "progress": progress["progress"],
            "results": progress["results"],
            "ai_analysis": progress.get("ai_analysis"),
            "exploit_suggestions": progress.get("exploit_suggestions", []),
            "attack_tree": progress.get("attack_tree")
        }
    
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if scan:
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "current_tool": None,
            "progress": 100,
            "results": scan.get("results", {}),
            "ai_analysis": scan.get("ai_analysis"),
            "exploit_suggestions": scan.get("exploit_suggestions", []),
            "attack_tree": scan.get("attack_tree")
        }
    
    raise HTTPException(status_code=404, detail="Scan not found")

@api_router.get("/scan/{scan_id}/tree")
async def get_attack_tree(scan_id: str):
    """Get attack tree for a scan"""
    if scan_id in attack_trees:
        return attack_trees[scan_id]
    
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0, "attack_tree": 1})
    if scan and "attack_tree" in scan:
        attack_trees[scan_id] = scan["attack_tree"]
        return scan["attack_tree"]
    
    raise HTTPException(status_code=404, detail="Attack tree not found")

@api_router.put("/scan/{scan_id}/tree/node/{node_id}")
async def update_tree_node(scan_id: str, node_id: str, update: UpdateNodeStatus):
    """Update attack tree node status"""
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
    
    # Update in database
    await db.scans.update_one(
        {"id": scan_id},
        {"$set": {"attack_tree": tree, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"message": "Node updated", "node_id": node_id, "status": update.status}

@api_router.post("/scan/{scan_id}/tree/node")
async def add_tree_node(scan_id: str, node: AttackNode):
    """Add a new node to attack tree"""
    if scan_id not in attack_trees:
        scan = await db.scans.find_one({"id": scan_id}, {"_id": 0, "attack_tree": 1})
        if scan and "attack_tree" in scan:
            attack_trees[scan_id] = scan["attack_tree"]
        else:
            raise HTTPException(status_code=404, detail="Attack tree not found")
    
    tree = attack_trees[scan_id]
    
    # Add node
    tree["nodes"][node.id] = node.model_dump()
    
    # Add to parent's children
    if node.parent_id == "root":
        tree["root"]["children"].append(node.id)
    elif node.parent_id in tree["nodes"]:
        tree["nodes"][node.parent_id]["children"].append(node.id)
    
    # Update in database
    await db.scans.update_one(
        {"id": scan_id},
        {"$set": {"attack_tree": tree, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"message": "Node added", "node": node.model_dump()}

@api_router.post("/metasploit/execute")
async def execute_metasploit(exploit: MetasploitExploit):
    """Execute a Metasploit module"""
    result = await run_metasploit_module(
        exploit.module,
        exploit.target_host,
        exploit.target_port,
        exploit.options
    )
    
    # Update attack tree node if provided
    if exploit.scan_id and exploit.node_id:
        if exploit.scan_id in attack_trees:
            tree = attack_trees[exploit.scan_id]
            if exploit.node_id in tree["nodes"]:
                node = tree["nodes"][exploit.node_id]
                node["status"] = "success" if result.get("success") else "failed"
                node["data"]["exploit_result"] = result
                
                # Add child node for access if session opened
                if result.get("session_opened"):
                    access_node_id = f"access_{uuid.uuid4().hex[:8]}"
                    access_node = {
                        "id": access_node_id,
                        "parent_id": exploit.node_id,
                        "type": "access",
                        "name": "Sesión Obtenida",
                        "description": f"Sesión Meterpreter/Shell abierta via {exploit.module}",
                        "status": "success",
                        "severity": "critical",
                        "data": {"session": True},
                        "children": []
                    }
                    tree["nodes"][access_node_id] = access_node
                    node["children"].append(access_node_id)
                
                await db.scans.update_one(
                    {"id": exploit.scan_id},
                    {"$set": {"attack_tree": tree, "updated_at": datetime.now(timezone.utc).isoformat()}}
                )
    
    return result

@api_router.get("/metasploit/modules")
async def search_metasploit_modules(query: str = "", category: str = ""):
    """Search for Metasploit modules"""
    modules = [
        # Exploits
        {"name": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "description": "Shellshock (CVE-2014-6271)", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/unix/webapp/php_cgi_arg_injection", "description": "PHP CGI Argument Injection", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/multi/http/tomcat_mgr_upload", "description": "Tomcat Manager Upload", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/multi/http/struts2_content_type_ognl", "description": "Apache Struts 2 RCE", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/windows/smb/ms17_010_eternalblue", "description": "EternalBlue SMB RCE", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/multi/http/jenkins_script_console", "description": "Jenkins Script Console RCE", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/unix/webapp/drupal_drupalgeddon2", "description": "Drupalgeddon2 RCE", "rank": "excellent", "category": "exploit"},
        {"name": "exploit/multi/http/wp_crop_rce", "description": "WordPress Crop RCE", "rank": "excellent", "category": "exploit"},
        # Auxiliary
        {"name": "auxiliary/scanner/http/dir_scanner", "description": "HTTP Directory Scanner", "rank": "normal", "category": "auxiliary"},
        {"name": "auxiliary/scanner/http/http_version", "description": "HTTP Version Detection", "rank": "normal", "category": "auxiliary"},
        {"name": "auxiliary/scanner/ssh/ssh_login", "description": "SSH Login Bruteforce", "rank": "normal", "category": "auxiliary"},
        {"name": "auxiliary/scanner/smb/smb_ms17_010", "description": "MS17-010 SMB Scanner", "rank": "normal", "category": "auxiliary"},
        {"name": "auxiliary/scanner/http/wordpress_scanner", "description": "WordPress Scanner", "rank": "normal", "category": "auxiliary"},
        {"name": "auxiliary/scanner/mysql/mysql_login", "description": "MySQL Login Bruteforce", "rank": "normal", "category": "auxiliary"},
        # Post
        {"name": "post/multi/gather/env", "description": "Gather Environment Variables", "rank": "normal", "category": "post"},
        {"name": "post/linux/gather/hashdump", "description": "Linux Password Hash Dump", "rank": "normal", "category": "post"},
        {"name": "post/windows/gather/hashdump", "description": "Windows Password Hash Dump", "rank": "normal", "category": "post"},
    ]
    
    filtered = modules
    
    if category:
        filtered = [m for m in filtered if m["category"] == category]
    
    if query:
        filtered = [m for m in filtered if query.lower() in m["name"].lower() or query.lower() in m["description"].lower()]
    
    return {"modules": filtered}

@api_router.get("/scan/history", response_model=List[ScanHistoryItem])
async def get_scan_history():
    """Get list of all completed scans"""
    scans = await db.scans.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    history = []
    for scan in scans:
        vuln_count = 0
        if "results" in scan:
            for tool, result in scan["results"].items():
                if isinstance(result, dict):
                    if "vulnerabilities" in result:
                        vuln_count += len(result["vulnerabilities"])
                    if "ports" in result:
                        vuln_count += len(result["ports"])
        
        history.append(ScanHistoryItem(
            id=scan["id"],
            target=scan["target"],
            status=scan["status"],
            tools_used=scan.get("tools_used", []),
            vulnerabilities_found=vuln_count,
            created_at=scan["created_at"]
        ))
    
    return history

@api_router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Get full scan report for export"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "report": scan,
        "generated_at": datetime.now(timezone.utc).isoformat()
    }

@api_router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from history"""
    result = await db.scans.delete_one({"id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_id in scan_progress:
        del scan_progress[scan_id]
    if scan_id in attack_trees:
        del attack_trees[scan_id]
    
    return {"message": "Scan deleted", "scan_id": scan_id}

@api_router.post("/ai/analyze")
async def manual_ai_analysis(request: AIAnalysisRequest):
    """Manually trigger AI analysis on results"""
    target = "unknown"
    
    scan = await db.scans.find_one({"id": request.scan_id}, {"_id": 0})
    if scan:
        target = scan.get("target", "unknown")
    
    result = await analyze_with_kimi(request.results, target)
    return result

@api_router.get("/tools")
async def get_available_tools():
    """Get list of available pentesting tools"""
    tools = [
        {"id": "waf", "name": "WAF Detection", "description": "Detecta Web Application Firewalls usando wafw00f", "icon": "shield"},
        {"id": "nmap", "name": "Nmap", "description": "Escaneo de puertos y detección de servicios", "icon": "radar"},
        {"id": "nikto", "name": "Nikto", "description": "Escaneo de vulnerabilidades web", "icon": "bug"},
        {"id": "whatweb", "name": "WhatWeb", "description": "Fingerprinting de tecnologías web", "icon": "fingerprint"},
        {"id": "subfinder", "name": "Subfinder", "description": "Enumeración de subdominios", "icon": "globe"},
        {"id": "sn1per", "name": "Sn1per", "description": "Framework de reconocimiento automatizado", "icon": "crosshair"}
    ]
    return {"tools": tools}

# Include the router in the main app
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
