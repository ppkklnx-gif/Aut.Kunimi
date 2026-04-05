#!/usr/bin/env python3
"""
Red Team Framework v5.0 - Setup Agent
Agente inteligente de instalación y diagnóstico.
Usa Kimi AI para analizar errores y sugerir soluciones.
Interactivo: pregunta al operador cuando necesita información.

Uso: python3 setup_agent.py
"""
import os
import sys
import json
import time
import shutil
import subprocess
import socket
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ============================================================
# COLORES TERMINAL
# ============================================================
class C:
    R  = "\033[91m"   # rojo
    G  = "\033[92m"   # verde
    Y  = "\033[93m"   # amarillo
    B  = "\033[94m"   # azul
    M  = "\033[95m"   # magenta
    CY = "\033[96m"   # cyan
    W  = "\033[97m"   # blanco
    D  = "\033[90m"   # dim
    BOLD = "\033[1m"
    X  = "\033[0m"    # reset

BANNER = f"""
{C.R}╔══════════════════════════════════════════════════════════╗
║{C.G}  ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗  {C.R}║
║{C.G}  ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║  {C.R}║
║{C.G}  ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║  {C.R}║
║{C.G}  ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║  {C.R}║
║{C.G}  ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║  {C.R}║
║{C.G}  ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  {C.R}║
║{C.CY}              SETUP AGENT v5.0 // Kimi AI Powered             {C.R}║
╚══════════════════════════════════════════════════════════╝{C.X}
"""

# ============================================================
# GLOBALS
# ============================================================
SCRIPT_DIR = Path(__file__).parent.resolve()
BACKEND_DIR = SCRIPT_DIR / "backend"
FRONTEND_DIR = SCRIPT_DIR / "frontend"
ENV_BACKEND = BACKEND_DIR / ".env"
ENV_FRONTEND = FRONTEND_DIR / ".env"

KIMI_API_KEY = ""
KIMI_API_URL = "https://api.moonshot.ai/v1/chat/completions"

# Acumulador de issues para AI
issues_log: List[Dict] = []
fixes_applied: List[str] = []

# ============================================================
# UTILIDADES
# ============================================================
def ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"{C.CY}[?]{C.X} {prompt}{hint}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default

def ask_yn(prompt: str, default: bool = True) -> bool:
    yn = "S/n" if default else "s/N"
    try:
        val = input(f"{C.CY}[?]{C.X} {prompt} [{yn}]: ").strip().lower()
        if not val:
            return default
        return val in ("s", "si", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return default

def ok(msg: str):
    print(f"  {C.G}[+]{C.X} {msg}")

def warn(msg: str):
    print(f"  {C.Y}[!]{C.X} {msg}")

def fail(msg: str):
    print(f"  {C.R}[-]{C.X} {msg}")

def info(msg: str):
    print(f"  {C.B}[*]{C.X} {msg}")

def header(msg: str):
    print(f"\n{C.BOLD}{C.CY}{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}{C.X}")

def run(cmd: str, timeout: int = 30, cwd: str = None) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=cwd
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)

def cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None

def port_open(host: str, port: int, timeout: float = 3) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

def log_issue(component: str, severity: str, desc: str, stdout: str = "", stderr: str = ""):
    issues_log.append({
        "component": component, "severity": severity,
        "description": desc, "stdout": stdout[:500], "stderr": stderr[:500]
    })

def load_env(path: Path) -> Dict[str, str]:
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env

def save_env(path: Path, env: Dict[str, str]):
    lines = []
    for k, v in env.items():
        if any(c in v for c in (" ", "#", "=")) and not v.startswith('"'):
            lines.append(f'{k}="{v}"')
        else:
            lines.append(f'{k}={v}')
    path.write_text("\n".join(lines) + "\n")

# ============================================================
# KIMI AI INTEGRATION
# ============================================================
def ask_kimi(prompt: str, context: str = "") -> str:
    """Consulta a Kimi AI para diagnosticar o resolver problemas"""
    if not KIMI_API_KEY:
        return "[AI no disponible - KIMI_API_KEY no configurada]"

    try:
        import httpx
    except ImportError:
        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            data = json.dumps({
                "model": "kimi-k2-0711-preview",
                "messages": [
                    {"role": "system", "content": "Eres un experto en Red Team, Kali Linux, Metasploit, Sliver C2, MongoDB, React y FastAPI. Responde en espanol, conciso y tecnico. Da comandos exactos."},
                    {"role": "user", "content": f"{context}\n\n{prompt}"}
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            }).encode()
            req = urllib.request.Request(
                KIMI_API_URL,
                data=data,
                headers={
                    "Authorization": f"Bearer {KIMI_API_KEY}",
                    "Content-Type": "application/json"
                }
            )
            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                result = json.loads(resp.read().decode())
                return result["choices"][0]["message"]["content"]
        except Exception as e:
            return f"[AI Error: {e}]"

    try:
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                KIMI_API_URL,
                headers={"Authorization": f"Bearer {KIMI_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "kimi-k2-0711-preview",
                    "messages": [
                        {"role": "system", "content": "Eres un experto en Red Team, Kali Linux, Metasploit, Sliver C2, MongoDB, React y FastAPI. Responde en espanol, conciso y tecnico. Da comandos exactos."},
                        {"role": "user", "content": f"{context}\n\n{prompt}"}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 2000
                }
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            else:
                return f"[AI HTTP {resp.status_code}: {resp.text[:200]}]"
    except Exception as e:
        return f"[AI Error: {e}]"

# ============================================================
# CHECKS
# ============================================================
def check_system():
    header("FASE 1: Sistema Operativo")
    info(f"OS: {platform.system()} {platform.release()}")
    info(f"Python: {platform.python_version()}")
    info(f"User: {os.environ.get('USER', 'unknown')}")
    info(f"Directory: {SCRIPT_DIR}")

    # Check if running as root
    if os.geteuid() == 0 and not os.environ.get("SUDO_USER"):
        warn("Ejecutando como root sin SUDO_USER. Los logs podrian quedar con permisos de root.")
        warn("Recomendado: ejecutar como usuario normal o con 'sudo -E python3 setup_agent.py'")

    # Check distro
    code, out, _ = run("cat /etc/os-release 2>/dev/null | head -3")
    if "kali" in out.lower():
        ok("Kali Linux detectado")
    elif "debian" in out.lower() or "ubuntu" in out.lower():
        ok(f"Debian/Ubuntu detectado (compatible)")
    else:
        warn(f"Distro no estandar detectada. Puede requerir ajustes manuales.")


def check_dependencies() -> List[str]:
    header("FASE 2: Dependencias del Sistema")
    missing = []
    tools = {
        "python3": "Python 3",
        "pip3": "pip (Python package manager)",
        "node": "Node.js",
        "yarn": "Yarn (React package manager)",
        "mongod": "MongoDB Server",
        "mongosh": "MongoDB Shell (opcional)",
        "nmap": "Nmap (scanner)",
        "git": "Git",
    }
    optional_tools = {
        "msfconsole": "Metasploit Framework",
        "msfvenom": "MSFvenom (payload generator)",
        "msfrpcd": "Metasploit RPC Daemon",
        "nikto": "Nikto (web scanner)",
        "gobuster": "Gobuster (directory bruteforcer)",
        "sliver-server": "Sliver C2 Server",
        "sliver-client": "Sliver C2 Client",
        "chisel": "Chisel (tunneling)",
    }

    for cmd, name in tools.items():
        if cmd_exists(cmd):
            code, out, _ = run(f"{cmd} --version 2>/dev/null || {cmd} -v 2>/dev/null")
            ver = out.split("\n")[0][:60] if out else ""
            ok(f"{name}: {ver or 'installed'}")
        else:
            fail(f"{name}: NO ENCONTRADO")
            missing.append(cmd)
            log_issue("dependency", "critical", f"{name} ({cmd}) not installed")

    print(f"\n  {C.D}--- Herramientas opcionales ---{C.X}")
    for cmd, name in optional_tools.items():
        if cmd_exists(cmd):
            ok(f"{name}: disponible")
        else:
            warn(f"{name}: no encontrado (opcional)")

    return missing


def install_missing(missing: List[str]):
    if not missing:
        return

    header("INSTALACION DE DEPENDENCIAS FALTANTES")
    info(f"Faltan: {', '.join(missing)}")

    if not ask_yn("Intentar instalar automaticamente?"):
        warn("Instalacion omitida. Instala manualmente antes de continuar.")
        return

    apt_map = {
        "python3": "python3",
        "pip3": "python3-pip",
        "node": None,  # special handling
        "yarn": None,   # special handling
        "mongod": None,  # special handling
        "mongosh": "mongosh",
        "nmap": "nmap",
        "git": "git",
    }

    for tool in missing:
        pkg = apt_map.get(tool)

        if tool == "node":
            info("Instalando Node.js 18...")
            run("curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -", timeout=60)
            code, _, err = run("sudo apt-get install -y nodejs", timeout=120)
            if code == 0:
                ok("Node.js instalado")
                fixes_applied.append("Installed Node.js 18")
            else:
                fail(f"Error instalando Node.js: {err[:100]}")
                log_issue("install", "critical", f"Node.js install failed: {err[:200]}")

        elif tool == "yarn":
            info("Instalando Yarn...")
            run("sudo npm install -g yarn", timeout=60)
            if cmd_exists("yarn"):
                ok("Yarn instalado")
                fixes_applied.append("Installed Yarn")
            else:
                fail("Yarn no se instalo correctamente")

        elif tool == "mongod":
            info("Instalando MongoDB...")
            cmds = [
                "curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg 2>/dev/null",
                'echo "deb [signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list',
                "sudo apt-get update -qq",
                "sudo apt-get install -y mongodb-org"
            ]
            success = True
            for cmd in cmds:
                code, _, err = run(cmd, timeout=120)
                if code != 0 and "mongodb-org" in cmd:
                    success = False
                    fail(f"MongoDB install step failed: {err[:100]}")
                    log_issue("install", "critical", f"MongoDB: {err[:200]}")
                    break
            if success:
                ok("MongoDB instalado")
                fixes_applied.append("Installed MongoDB 7.0")

        elif pkg:
            info(f"Instalando {pkg}...")
            code, _, err = run(f"sudo apt-get install -y {pkg}", timeout=120)
            if code == 0:
                ok(f"{pkg} instalado")
                fixes_applied.append(f"Installed {pkg}")
            else:
                fail(f"Error: {err[:100]}")


def check_mongodb() -> bool:
    header("FASE 3: MongoDB")

    # Check if running
    code, _, _ = run("pgrep mongod")
    if code == 0:
        ok("MongoDB: proceso activo")
    else:
        warn("MongoDB no esta corriendo")
        if ask_yn("Iniciar MongoDB?"):
            run("sudo systemctl start mongod 2>/dev/null || sudo mongod --fork --logpath /var/log/mongodb/mongod.log --dbpath /var/lib/mongodb 2>/dev/null", timeout=10)
            time.sleep(2)
            code, _, _ = run("pgrep mongod")
            if code == 0:
                ok("MongoDB iniciado")
                fixes_applied.append("Started MongoDB")
            else:
                fail("No se pudo iniciar MongoDB")
                # Check journal config issue
                code, out, _ = run("cat /etc/mongod.conf 2>/dev/null | grep journal")
                if "true" in out.lower():
                    warn("Posible conflicto con journal en /etc/mongod.conf")
                    if ask_yn("Intentar fix de journal (comentar journal.enabled)?"):
                        run("sudo sed -i 's/journal:/# journal:/' /etc/mongod.conf")
                        run("sudo sed -i 's/enabled: true/# enabled: true/' /etc/mongod.conf")
                        run("sudo systemctl start mongod", timeout=10)
                        time.sleep(2)
                        if port_open("127.0.0.1", 27017):
                            ok("MongoDB iniciado tras fix de journal")
                            fixes_applied.append("Fixed MongoDB journal config")
                        else:
                            fail("MongoDB sigue sin iniciar")
                            log_issue("mongodb", "critical", "Cannot start MongoDB even after journal fix")
                            return False
                else:
                    log_issue("mongodb", "critical", "MongoDB won't start")
                    return False

    # Test connectivity
    if port_open("127.0.0.1", 27017):
        ok("MongoDB: puerto 27017 abierto")
        return True
    else:
        fail("MongoDB: puerto 27017 NO accesible")
        log_issue("mongodb", "critical", "MongoDB port 27017 not reachable")
        return False


def check_backend_env() -> Dict[str, str]:
    header("FASE 4: Configuracion Backend (.env)")
    env = load_env(ENV_BACKEND)

    if not env:
        warn("backend/.env no existe o esta vacio")
        info("Creando configuracion...")
        env = {}

    # Required keys
    required = {
        "MONGO_URL": "mongodb://localhost:27017",
        "DB_NAME": "redteam_framework",
    }

    # Interactive keys
    interactive = {
        "KIMI_API_KEY": ("API Key de Moonshot/Kimi (para analisis AI)", ""),
        "MSF_RPC_TOKEN": ("Token de msfrpcd (password del daemon)", ""),
        "MSF_RPC_HOST": ("IP del msfrpcd (127.0.0.1 si es local, IP de VPS si remoto)", "127.0.0.1"),
        "MSF_RPC_PORT": ("Puerto de msfrpcd", "55553"),
        "SLIVER_CONFIG_PATH": ("Ruta al archivo de config de Sliver operator (.cfg)", ""),
    }

    # Set defaults
    for k, v in required.items():
        if k not in env or not env[k]:
            env[k] = v
            ok(f"{k} = {v}")
        else:
            ok(f"{k} = {env[k]}")

    # Interactive prompts
    for k, (desc, default) in interactive.items():
        current = env.get(k, "")
        if current:
            ok(f"{k} = {current[:40]}{'...' if len(current) > 40 else ''}")
            if not ask_yn(f"  Mantener valor actual de {k}?"):
                val = ask(desc, current)
                env[k] = val
        else:
            val = ask(desc, default)
            env[k] = val
            if val:
                ok(f"{k} configurado")
            else:
                warn(f"{k} vacio (funcionalidad limitada)")

    # Validate SLIVER_CONFIG_PATH
    sliver_path = env.get("SLIVER_CONFIG_PATH", "")
    if sliver_path:
        expanded = os.path.expanduser(sliver_path)
        if os.path.isdir(expanded):
            warn(f"SLIVER_CONFIG_PATH es un DIRECTORIO: {expanded}")
            # Look for config files inside
            candidates = []
            for root, dirs, files in os.walk(expanded):
                for f in files:
                    if f.endswith(".cfg"):
                        candidates.append(os.path.join(root, f))
                break  # only first level
            if candidates:
                info(f"Archivos .cfg encontrados: {candidates}")
                env["SLIVER_CONFIG_PATH"] = candidates[0]
                ok(f"SLIVER_CONFIG_PATH corregido a: {candidates[0]}")
                fixes_applied.append(f"Fixed SLIVER_CONFIG_PATH: directory -> {candidates[0]}")
            else:
                fail(f"No se encontraron archivos .cfg en {expanded}")
                info("Genera uno con: sliver > new-operator --name redteam --lhost 127.0.0.1")
                env["SLIVER_CONFIG_PATH"] = ""
        elif os.path.isfile(expanded):
            ok(f"SLIVER_CONFIG_PATH: archivo valido ({expanded})")
        elif sliver_path:
            warn(f"SLIVER_CONFIG_PATH: archivo no existe ({expanded})")

    # Add optional keys with defaults
    env.setdefault("CORS_ORIGINS", "*")

    save_env(ENV_BACKEND, env)
    ok("backend/.env guardado")
    return env


def check_frontend_env():
    header("FASE 5: Configuracion Frontend (.env)")
    env = load_env(ENV_FRONTEND)

    current_url = env.get("REACT_APP_BACKEND_URL", "")
    if current_url:
        ok(f"REACT_APP_BACKEND_URL = {current_url}")
    else:
        warn("REACT_APP_BACKEND_URL no configurado")

    default_url = "http://localhost:8001"
    if not current_url or ask_yn(f"Cambiar URL del backend? (actual: {current_url or 'ninguna'})"):
        url = ask("URL del backend", current_url or default_url)
        env["REACT_APP_BACKEND_URL"] = url

    save_env(ENV_FRONTEND, env)
    ok("frontend/.env guardado")


def install_python_deps():
    header("FASE 6: Dependencias Python (Backend)")
    req_file = BACKEND_DIR / "requirements.txt"
    if not req_file.exists():
        warn("requirements.txt no encontrado")
        return

    info("Instalando dependencias Python...")
    code, out, err = run(f"pip3 install -r {req_file}", timeout=180, cwd=str(BACKEND_DIR))
    if code == 0:
        ok("Dependencias Python instaladas")
    else:
        fail(f"Error instalando dependencias: {err[:200]}")
        log_issue("python_deps", "high", f"pip install failed: {err[:300]}")

        if ask_yn("Consultar a Kimi AI para diagnosticar?"):
            diagnosis = ask_kimi(
                f"Error instalando dependencias Python con pip:\n{err[:500]}",
                "Sistema: Kali Linux. requirements.txt contiene: fastapi, uvicorn, motor, httpx, fpdf2, pymetasploit3, sliver-py, websockets"
            )
            print(f"\n{C.M}[AI KIMI]{C.X} {diagnosis}\n")


def install_frontend_deps():
    header("FASE 7: Dependencias Frontend (React)")
    pkg_json = FRONTEND_DIR / "package.json"
    if not pkg_json.exists():
        fail("package.json no encontrado")
        return

    node_modules = FRONTEND_DIR / "node_modules"
    if node_modules.exists() and (node_modules / "react").exists():
        ok("node_modules existe, verificando...")
        code, _, _ = run("yarn check --verify-tree 2>/dev/null || true", cwd=str(FRONTEND_DIR))
        if ask_yn("Reinstalar dependencias frontend?", default=False):
            pass
        else:
            ok("Dependencias frontend OK")
            return

    info("Instalando dependencias con yarn...")
    code, out, err = run("yarn install", timeout=300, cwd=str(FRONTEND_DIR))
    if code == 0:
        ok("Dependencias frontend instaladas")
    else:
        fail(f"Error: {err[:200]}")
        log_issue("frontend_deps", "high", f"yarn install failed: {err[:300]}")


def check_msf_rpc(env: Dict[str, str]) -> bool:
    header("FASE 8: Metasploit RPC")
    token = env.get("MSF_RPC_TOKEN", "")
    host = env.get("MSF_RPC_HOST", "127.0.0.1")
    port_str = env.get("MSF_RPC_PORT", "55553")

    if not token:
        warn("MSF_RPC_TOKEN no configurado. MSF RPC deshabilitado.")
        info("Para habilitar: msfrpcd -P TU_PASSWORD -S -a 0.0.0.0 -p 55553")
        return False

    port = int(port_str)
    info(f"Probando conexion a msfrpcd en {host}:{port}...")

    if not port_open(host, port, timeout=5):
        fail(f"Puerto {host}:{port} NO accesible")

        # Check if msfrpcd is installed
        if cmd_exists("msfrpcd"):
            if ask_yn(f"Iniciar msfrpcd en {host}:{port}?"):
                listen_addr = host if host in ("127.0.0.1", "0.0.0.0", "localhost") else "0.0.0.0"
                run(f"msfrpcd -P '{token}' -S -a {listen_addr} -p {port} &", timeout=5)
                time.sleep(3)
                if port_open(host, port):
                    ok("msfrpcd iniciado correctamente")
                    fixes_applied.append("Started msfrpcd")
                    return True
                else:
                    fail("msfrpcd no pudo iniciar")
                    code, out, err = run("tail -5 /var/log/msfrpcd.log 2>/dev/null || journalctl -u msfrpcd --tail 5 2>/dev/null")
                    if out or err:
                        info(f"Log: {(out or err)[:200]}")
                    log_issue("msf_rpc", "critical", f"msfrpcd won't start on {host}:{port}")
        else:
            warn("msfrpcd no encontrado. Instala Metasploit Framework.")

        if host not in ("127.0.0.1", "localhost", "0.0.0.0"):
            info(f"El host {host} es remoto. Verifica:")
            info(f"  1. msfrpcd esta corriendo en {host}")
            info(f"  2. El puerto {port} esta abierto en el firewall")
            info(f"  3. Si usas Tailscale/VPN, verifica la ruta de red")
        return False
    else:
        ok(f"Puerto {host}:{port} ABIERTO")

    # Try actual RPC handshake
    info("Verificando handshake RPC...")
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        for ssl_mode in (True, False):
            try:
                client = MsfRpcClient(token, server=host, port=port, ssl=ssl_mode)
                version = client.call("core.version")
                proto = "SSL" if ssl_mode else "plaintext"
                ok(f"MSF RPC CONECTADO ({proto})")
                ok(f"  Version: {version.get('version', '?')}")
                ok(f"  Ruby: {version.get('ruby', '?')}")

                # List sessions
                sessions = client.call("session.list")
                ok(f"  Sesiones activas: {len(sessions)}")
                for sid, sinfo in sessions.items():
                    info(f"    Session {sid}: {sinfo.get('type','')} -> {sinfo.get('tunnel_peer','')}")
                return True
            except Exception as e:
                err_str = str(e)
                if "SSL" in err_str or "ssl" in err_str:
                    continue
                if "401" in err_str or "auth" in err_str.lower():
                    fail(f"AUTENTICACION FALLIDA: Token incorrecto")
                    log_issue("msf_rpc", "critical", f"Auth failed: {err_str}")
                    info("Verifica que MSF_RPC_TOKEN coincide con el -P de msfrpcd")
                    return False
                fail(f"Handshake error ({proto}): {err_str[:100]}")

        fail("No se pudo establecer handshake (ni SSL ni plaintext)")
        log_issue("msf_rpc", "critical", "RPC handshake failed both SSL and plain")

        if ask_yn("Consultar a Kimi AI para diagnosticar?"):
            diagnosis = ask_kimi(
                f"msfrpcd corriendo en {host}:{port}, puerto abierto, pero handshake RPC falla.\nToken: {'set' if token else 'not set'}\nError al conectar con pymetasploit3.",
                f"Entorno: Kali Linux, pymetasploit3, host={host}, port={port}, SSL probado."
            )
            print(f"\n{C.M}[AI KIMI]{C.X} {diagnosis}\n")
        return False

    except ImportError:
        warn("pymetasploit3 no instalado. Instalando...")
        run("pip3 install pymetasploit3", timeout=60)
        fixes_applied.append("Installed pymetasploit3")
        return False


def check_sliver(env: Dict[str, str]) -> bool:
    header("FASE 9: Sliver C2")
    config_path = env.get("SLIVER_CONFIG_PATH", "")

    if not config_path:
        warn("SLIVER_CONFIG_PATH no configurado. Sliver C2 deshabilitado.")
        if cmd_exists("sliver-server") or cmd_exists("sliver"):
            info("Sliver esta instalado. Para configurar:")
            info("  1. sliver-server (en otra terminal)")
            info("  2. Dentro de Sliver: new-operator --name redteam --lhost 127.0.0.1 --save /home/USER/.sliver-client/configs/default.cfg")
            info("  3. Agrega la ruta al .env: SLIVER_CONFIG_PATH=/home/USER/.sliver-client/configs/default.cfg")
        return False

    expanded = os.path.expanduser(config_path)
    if not os.path.exists(expanded):
        fail(f"Archivo de config no existe: {expanded}")
        return False

    if os.path.isdir(expanded):
        fail(f"SLIVER_CONFIG_PATH apunta a un DIRECTORIO, no a un archivo!")
        info(f"  Ruta: {expanded}")
        info("  Debe apuntar al archivo .cfg, ejemplo: /home/pp/.sliver-client/configs/default.cfg")
        return False

    ok(f"Config file: {expanded}")

    # Try to connect
    info("Intentando conexion a Sliver...")
    try:
        import asyncio
        from sliver import SliverClientConfig, SliverClient

        async def _test():
            config = SliverClientConfig.parse_config_file(expanded)
            client = SliverClient(config)
            await client.connect()
            version = await client.version()
            return version

        version = asyncio.run(_test())
        ok(f"Sliver CONECTADO v{version.Major}.{version.Minor}.{version.Patch}")

        # List sessions
        async def _sessions():
            config = SliverClientConfig.parse_config_file(expanded)
            client = SliverClient(config)
            await client.connect()
            return await client.sessions()

        sessions = asyncio.run(_sessions())
        ok(f"Sesiones activas: {len(sessions)}")
        for s in sessions:
            info(f"  {s.Name} @ {s.Hostname} [{s.OS}/{s.Arch}] via {s.Transport}")
        return True

    except ImportError:
        warn("sliver-py no instalado. Instalando...")
        run("pip3 install sliver-py", timeout=60)
        fixes_applied.append("Installed sliver-py")
        return False
    except Exception as e:
        fail(f"Conexion a Sliver fallida: {e}")
        log_issue("sliver", "high", f"Sliver connection failed: {e}")
        if "refused" in str(e).lower():
            info("Asegurate que sliver-server esta corriendo")
        return False


def check_services():
    header("FASE 10: Verificacion de Servicios")

    # Backend
    info("Probando Backend (FastAPI)...")
    if port_open("127.0.0.1", 8001):
        ok("Backend: puerto 8001 ABIERTO")
        code, out, _ = run("curl -s http://localhost:8001/api/")
        if code == 0 and "Red Team" in out:
            ok(f"Backend respondiendo: {out[:80]}")
        else:
            warn("Backend esta corriendo pero no responde correctamente")
    else:
        warn("Backend NO esta corriendo en puerto 8001")
        if ask_yn("Iniciar backend ahora?"):
            real_user = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
            log_dir = SCRIPT_DIR / "logs"
            log_dir.mkdir(exist_ok=True)

            if real_user and os.geteuid() == 0:
                run(f"su - {real_user} -c 'cd {BACKEND_DIR} && nohup uvicorn server:app --host 0.0.0.0 --port 8001 --reload > {log_dir}/backend.log 2>&1 &'")
            else:
                run(f"cd {BACKEND_DIR} && nohup uvicorn server:app --host 0.0.0.0 --port 8001 --reload > {log_dir}/backend.log 2>&1 &")

            time.sleep(3)
            if port_open("127.0.0.1", 8001):
                ok("Backend iniciado")
                fixes_applied.append("Started backend")
            else:
                fail("Backend no pudo iniciar")
                code, out, err = run(f"tail -10 {log_dir}/backend.log 2>/dev/null")
                if out or err:
                    fail(f"Log: {(out or err)[:300]}")
                log_issue("backend", "critical", f"Backend failed to start: {(out or err)[:300]}")

    # Frontend
    info("Probando Frontend (React)...")
    if port_open("127.0.0.1", 3000):
        ok("Frontend: puerto 3000 ABIERTO")
    else:
        warn("Frontend NO esta corriendo en puerto 3000")
        if ask_yn("Iniciar frontend ahora?"):
            real_user = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
            log_dir = SCRIPT_DIR / "logs"
            log_dir.mkdir(exist_ok=True)

            if real_user and os.geteuid() == 0:
                run(f"su - {real_user} -c 'cd {FRONTEND_DIR} && nohup yarn start > {log_dir}/frontend.log 2>&1 &'")
            else:
                run(f"cd {FRONTEND_DIR} && nohup yarn start > {log_dir}/frontend.log 2>&1 &")

            info("Frontend iniciando (puede tardar 15-30 segundos)...")
            fixes_applied.append("Started frontend")


def run_full_test(env: Dict[str, str]):
    header("FASE 11: Test Funcional Completo")

    if not port_open("127.0.0.1", 8001):
        fail("Backend no disponible. Saltando tests.")
        return

    api = "http://localhost:8001/api"
    tests_passed = 0
    tests_total = 0

    def test(name: str, cmd: str, expect: str = "") -> bool:
        nonlocal tests_passed, tests_total
        tests_total += 1
        code, out, err = run(cmd)
        if code == 0 and (not expect or expect in out):
            ok(f"TEST: {name}")
            tests_passed += 1
            return True
        else:
            fail(f"TEST: {name}")
            if err:
                info(f"  Error: {err[:100]}")
            log_issue("test", "medium", f"Test failed: {name}", out[:200], err[:200])
            return False

    test("API root", f"curl -s {api}/", "Red Team")
    test("Config GET", f"curl -s {api}/config", "listener_ip")
    test("Chains", f"curl -s {api}/chains", "chains")
    test("MITRE tactics", f"curl -s {api}/mitre/tactics", "tactics")
    test("MSF modules", f"curl -s {api}/metasploit/modules", "modules")
    test("Payload templates", f"curl -s {api}/payloads/templates", "payloads")
    test("Scan history", f"curl -s {api}/scan/history", "[")
    test("C2 dashboard", f"curl -s {api}/c2/dashboard", "metasploit")
    test("MSF diagnostics", f"curl -s {api}/msf/diagnostics", "token_set")

    # Scan test
    info("Ejecutando scan de prueba...")
    code, out, _ = run(f"""curl -s -X POST {api}/scan/start -H "Content-Type: application/json" -d '{{"target":"testsite.com","scan_phases":["reconnaissance"],"tools":["nmap"]}}'""")
    if code == 0 and "scan_id" in out:
        try:
            scan_id = json.loads(out)["scan_id"]
            ok(f"Scan iniciado: {scan_id}")
            info("Esperando resultado (10s)...")
            time.sleep(10)
            code2, out2, _ = run(f"curl -s {api}/scan/{scan_id}/status")
            if code2 == 0:
                data = json.loads(out2)
                status = data.get("status", "unknown")
                if status == "completed":
                    ok(f"Scan completado: {status}")
                    tests_passed += 1
                else:
                    warn(f"Scan status: {status}")
                tests_total += 1
        except Exception as e:
            fail(f"Error en scan test: {e}")
            tests_total += 1

    print(f"\n  {C.BOLD}Resultado: {tests_passed}/{tests_total} tests pasados{C.X}")

    if tests_passed < tests_total:
        if ask_yn("Consultar a Kimi AI sobre los tests fallidos?"):
            failed_issues = [i for i in issues_log if i["component"] == "test"]
            diagnosis = ask_kimi(
                f"Tests fallidos en Red Team Framework:\n{json.dumps(failed_issues, indent=2)}",
                f"Backend corriendo en localhost:8001. MongoDB en localhost:27017."
            )
            print(f"\n{C.M}[AI KIMI]{C.X} {diagnosis}\n")


def ai_full_diagnosis():
    header("FASE 12: Diagnostico AI Completo")

    if not issues_log:
        ok("No se detectaron problemas. Sistema operativo.")
        return

    info(f"Issues detectados: {len(issues_log)}")
    for i, issue in enumerate(issues_log):
        sev_color = C.R if issue["severity"] == "critical" else C.Y if issue["severity"] == "high" else C.B
        print(f"  {sev_color}[{issue['severity'].upper()}]{C.X} [{issue['component']}] {issue['description']}")

    if not ask_yn("Enviar diagnostico a Kimi AI para analisis y solucion?"):
        return

    context = f"""
Sistema: Kali Linux
Framework: Red Team Automation v5.0
Backend: FastAPI + MongoDB + pymetasploit3 + sliver-py
Frontend: React + Tailwind + Shadcn UI
Issues detectados: {len(issues_log)}
Fixes ya aplicados: {json.dumps(fixes_applied)}
"""

    prompt = f"""Analiza estos problemas del Red Team Framework y dame soluciones EXACTAS (comandos especificos para Kali Linux):

{json.dumps(issues_log, indent=2, ensure_ascii=False)}

Para cada issue:
1. Causa raiz probable
2. Comando exacto para solucionarlo
3. Como verificar que se resolvio
"""

    info("Consultando a Kimi AI...")
    diagnosis = ask_kimi(prompt, context)
    print(f"\n{C.M}{'='*60}")
    print(f"  DIAGNOSTICO KIMI AI")
    print(f"{'='*60}{C.X}\n")
    print(diagnosis)
    print()


def summary():
    header("RESUMEN FINAL")

    if fixes_applied:
        print(f"\n  {C.G}Correcciones aplicadas:{C.X}")
        for fix in fixes_applied:
            print(f"    {C.G}[+]{C.X} {fix}")

    if issues_log:
        critical = [i for i in issues_log if i["severity"] == "critical"]
        high = [i for i in issues_log if i["severity"] == "high"]
        medium = [i for i in issues_log if i["severity"] == "medium"]

        if critical:
            print(f"\n  {C.R}Issues criticos sin resolver: {len(critical)}{C.X}")
            for i in critical:
                print(f"    {C.R}[-]{C.X} [{i['component']}] {i['description']}")
        if high:
            print(f"\n  {C.Y}Issues altos: {len(high)}{C.X}")
            for i in high:
                print(f"    {C.Y}[!]{C.X} [{i['component']}] {i['description']}")
    else:
        print(f"\n  {C.G}{C.BOLD}SISTEMA OPERATIVO - Sin issues detectados{C.X}")

    print(f"\n  {C.CY}Para iniciar el framework:{C.X}")
    print(f"    ./start_redteam.sh")
    print(f"\n  {C.CY}O manualmente:{C.X}")
    print(f"    cd backend && uvicorn server:app --host 0.0.0.0 --port 8001 --reload &")
    print(f"    cd frontend && yarn start &")
    print(f"\n  {C.CY}Abrir en navegador:{C.X} http://localhost:3000")
    print()


# ============================================================
# MAIN
# ============================================================
def main():
    global KIMI_API_KEY

    print(BANNER)

    # Load existing Kimi key
    if ENV_BACKEND.exists():
        env = load_env(ENV_BACKEND)
        KIMI_API_KEY = env.get("KIMI_API_KEY", "")

    if KIMI_API_KEY:
        ok(f"Kimi AI: Key encontrada ({KIMI_API_KEY[:10]}...)")
    else:
        warn("Kimi AI: Key no encontrada. Diagnostico AI no disponible.")
        key = ask("Introduce tu KIMI_API_KEY (o Enter para omitir)")
        if key:
            KIMI_API_KEY = key

    # Run all phases
    check_system()
    missing = check_dependencies()
    if missing:
        install_missing(missing)

    mongo_ok = check_mongodb()
    backend_env = check_backend_env()
    KIMI_API_KEY = backend_env.get("KIMI_API_KEY", KIMI_API_KEY)  # refresh after config
    check_frontend_env()
    install_python_deps()
    install_frontend_deps()
    check_msf_rpc(backend_env)
    check_sliver(backend_env)
    check_services()
    run_full_test(backend_env)
    ai_full_diagnosis()
    summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.Y}[!] Interrumpido por el usuario{C.X}")
        sys.exit(1)
