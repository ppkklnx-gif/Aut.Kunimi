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
            # WAF Detection with wafw00f
            cmd = ["wafw00f", target, "-o", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return parse_waf_output(result.stdout + result.stderr)
            
        elif tool == "nmap":
            # Nmap scan - basic service detection
            cmd = ["nmap", "-sV", "-sC", "--top-ports", "100", "-T4", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return parse_nmap_output(result.stdout)
            
        elif tool == "nikto":
            # Nikto web vulnerability scan
            cmd = ["nikto", "-h", target, "-Format", "txt", "-timeout", "10"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return parse_nikto_output(result.stdout + result.stderr)
            
        elif tool == "whatweb":
            # WhatWeb fingerprinting
            cmd = ["whatweb", "-v", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"fingerprint": result.stdout, "raw": result.stdout}
            
        elif tool == "subfinder":
            # Subfinder subdomain enumeration
            cmd = ["subfinder", "-d", target, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            return {"subdomains": subdomains, "count": len(subdomains)}
            
        elif tool == "sn1per":
            # Sn1per recon (simplified output)
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

async def analyze_with_kimi(results: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Send results to Kimi K2 for AI analysis"""
    if not KIMI_API_KEY:
        return {
            "analysis": "Kimi API key not configured. Please add KIMI_API_KEY to your environment.",
            "exploits": []
        }
    
    prompt = f"""Eres un experto en ciberseguridad y pentesting. Analiza los siguientes resultados de escaneo para el objetivo: {target}

RESULTADOS DEL ESCANEO:
{json.dumps(results, indent=2, default=str)}

Por favor proporciona:
1. RESUMEN DE HALLAZGOS: Lista de vulnerabilidades encontradas ordenadas por severidad (Crítica, Alta, Media, Baja)
2. VECTORES DE ATAQUE: Posibles formas de explotar las vulnerabilidades encontradas
3. COMANDOS METASPLOIT: Sugiere módulos y comandos de Metasploit específicos para explotar las vulnerabilidades
4. COMANDOS SQLMAP: Si hay indicios de SQL Injection, proporciona comandos sqlmap
5. RECOMENDACIONES: Pasos a seguir para continuar el pentesting
6. MITIGACIONES: Cómo el objetivo podría protegerse

Responde en español y sé específico con los comandos."""

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                KIMI_API_URL,
                headers={
                    "Authorization": f"Bearer {KIMI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "kimi-k2-0711-preview",
                    "messages": [
                        {"role": "system", "content": "Eres un experto en ciberseguridad y pentesting con profundo conocimiento de Kali Linux, Metasploit, y técnicas de hacking ético."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 4096
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                ai_response = data["choices"][0]["message"]["content"]
                
                # Extract exploit suggestions
                exploits = []
                if "msfconsole" in ai_response.lower() or "metasploit" in ai_response.lower():
                    # Parse Metasploit commands from response
                    lines = ai_response.split('\n')
                    for line in lines:
                        if 'use ' in line.lower() or 'exploit/' in line.lower() or 'auxiliary/' in line.lower():
                            exploits.append({"type": "metasploit", "command": line.strip()})
                        if 'sqlmap' in line.lower():
                            exploits.append({"type": "sqlmap", "command": line.strip()})
                
                return {
                    "analysis": ai_response,
                    "exploits": exploits
                }
            else:
                return {
                    "analysis": f"Error de API Kimi: {response.status_code} - {response.text}",
                    "exploits": []
                }
                
    except Exception as e:
        logger.error(f"Error calling Kimi API: {str(e)}")
        return {
            "analysis": f"Error al conectar con Kimi: {str(e)}",
            "exploits": []
        }

async def run_scan_background(scan_id: str, target: str, scan_types: List[str]):
    """Background task to run all scans"""
    global scan_progress
    
    scan_progress[scan_id] = {
        "status": "running",
        "current_tool": None,
        "progress": 0,
        "results": {},
        "ai_analysis": None,
        "exploit_suggestions": []
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
    return {"message": "Kali Pentesting Automation Suite API", "version": "1.0.0"}

@api_router.post("/scan/start")
async def start_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """Start a new penetration test scan"""
    scan_id = str(uuid.uuid4())
    
    # Validate target
    target = scan.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Remove protocol for some tools
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    # Start background scan
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
            "exploit_suggestions": progress.get("exploit_suggestions", [])
        }
    
    # Check database
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if scan:
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "current_tool": None,
            "progress": 100,
            "results": scan.get("results", {}),
            "ai_analysis": scan.get("ai_analysis"),
            "exploit_suggestions": scan.get("exploit_suggestions", [])
        }
    
    raise HTTPException(status_code=404, detail="Scan not found")

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
    
    return {"message": "Scan deleted", "scan_id": scan_id}

@api_router.post("/ai/analyze")
async def manual_ai_analysis(request: AIAnalysisRequest):
    """Manually trigger AI analysis on results"""
    target = "unknown"
    
    # Get target from scan if exists
    if request.scan_id in scan_progress:
        pass
    else:
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

@api_router.get("/metasploit/modules")
async def search_metasploit_modules(query: str = ""):
    """Search for Metasploit modules"""
    # This would normally search MSF database
    # For demo, return common modules
    modules = [
        {"name": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "description": "Shellshock", "rank": "excellent"},
        {"name": "exploit/unix/webapp/php_cgi_arg_injection", "description": "PHP CGI Argument Injection", "rank": "excellent"},
        {"name": "exploit/multi/http/tomcat_mgr_upload", "description": "Tomcat Manager Upload", "rank": "excellent"},
        {"name": "auxiliary/scanner/http/dir_scanner", "description": "HTTP Directory Scanner", "rank": "normal"},
        {"name": "auxiliary/scanner/http/http_version", "description": "HTTP Version Detection", "rank": "normal"}
    ]
    
    if query:
        modules = [m for m in modules if query.lower() in m["name"].lower() or query.lower() in m["description"].lower()]
    
    return {"modules": modules}

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
