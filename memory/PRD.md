# Red Team Automation Framework v5.0 - PRD

## Problem Statement
Framework Red Team local para Kali Linux con orquestacion adaptativa, C2 (MSF RPC + Sliver), generador de payloads con LHOST global, UI estilo APT/Cyberpunk, y agente de instalacion con AI.

## What's Implemented

### Setup Agent con Kimi AI (Apr 2026)
- [x] setup_agent.py: 12 fases de verificacion automatica
- [x] Fase 1-2: Sistema operativo, dependencias (auto-install)
- [x] Fase 3: MongoDB (deteccion, start, fix journal config)
- [x] Fase 4-5: Backend/Frontend .env (interactivo, validacion de rutas)
- [x] Fase 6-7: Python deps (pip), Frontend deps (yarn)
- [x] Fase 8: MSF RPC (port check, SSL/plain handshake, auto-start msfrpcd)
- [x] Fase 9: Sliver C2 (path validation dir vs file, connection test)
- [x] Fase 10: Start services (backend uvicorn, frontend yarn)
- [x] Fase 11: Test funcional completo (9+ endpoints + scan test)
- [x] Fase 12: Diagnostico AI con Kimi (analisis de todos los issues)
- [x] Correccion automatica de SLIVER_CONFIG_PATH (directorio -> archivo)
- [x] Permisos de logs correctos (SUDO_USER detection)
- [x] Terminal con colores (status visual claro)

### C2 Resilience Layer (Apr 2026)
- [x] MSF RPC: SSL/non-SSL fallback, diagnostics, exponential backoff reconnect
- [x] Sliver: Config path validation, async reconnect
- [x] Frontend RECONNECT button + diagnostics panel

### UI - APT Style (Apr 2026)
- [x] 9 sections: Dashboard, Targets, Attack Graph, Chains, C2, Payloads, AI, Config, Logs
- [x] Payload Generator: 11 templates with LHOST auto-injection
- [x] Global Config: LHOST/LPORT persistent in MongoDB

### Core Backend
- [x] Adaptive orchestration, chains, credential vault, session manager
- [x] PDF reports, attack timeline, WebSocket updates

## Architecture
```
setup_agent.py - AI-powered setup and diagnostic agent (Kimi)
start_redteam.sh - Start script with permission handling
install.sh - Full installer for Kali
backend/server.py - FastAPI (50+ endpoints)
backend/modules/__init__.py - MSF RPC with reconnect
backend/modules/sliver_c2.py - Sliver with path validation
backend/modules/credential_vault.py
backend/modules/session_manager.py
frontend/src/App.js - React (9 sections)
frontend/src/App.css - Cyberpunk theme
```

## Backlog
### P1
- [ ] Refactorizar App.js en componentes modulares

### P2
- [ ] OpSec/Evasion, BloodHound AD, multi-target campaigns
- [ ] Payload obfuscation (shikata_ga_nai, XOR, base64)
