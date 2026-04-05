# Red Team Automation Framework v5.0 - PRD

## Problem Statement
Framework Red Team local para Kali Linux. Dockerizado con docker-compose (MongoDB, FastAPI, React/Nginx). Kali host solo para herramientas ofensivas (msfrpcd, sliver). Despliegue reproducible con un solo comando.

## What's Implemented

### Docker Deployment (Apr 2026)
- [x] docker-compose.yml: 3 servicios (mongo:7, backend, frontend)
- [x] backend/Dockerfile: Python 3.11 + nmap + nikto + gobuster
- [x] frontend/Dockerfile: Multi-stage (Node 18 build -> Nginx serve)
- [x] frontend/nginx.conf: Proxy /api -> backend:8001, WebSocket, SPA routing, 600s timeout
- [x] .env.docker: Template con todas las variables
- [x] DOCKER_DEPLOY.md: Documentacion completa con arquitectura y troubleshooting
- [x] GET /api/health: Diagnostico de conectividad (MongoDB, MSF, Sliver, Listener)
- [x] LISTENER_IP/LISTENER_PORT seed from env vars on startup
- [x] host.docker.internal para conectar a MSF/Sliver en Kali host

### Setup Agent con Kimi AI (Apr 2026)
- [x] setup_agent.py: 12 fases de verificacion automatica con AI

### C2 Resilience (Apr 2026)
- [x] MSF RPC: SSL/non-SSL fallback, diagnostics, exponential backoff reconnect
- [x] Sliver: Config path validation (dir vs file), async reconnect
- [x] RECONNECT button + diagnostics en frontend

### UI - APT Style (Apr 2026)
- [x] 9 sections: Dashboard, Targets, Attack Graph, Chains, C2, Payloads, AI, Config, Logs
- [x] Payload Generator: 11 templates con LHOST auto-injection
- [x] Global Config persistent en MongoDB

### Core Backend
- [x] Adaptive orchestration, chains, credential vault, session manager
- [x] PDF reports, attack timeline, WebSocket updates

## Architecture
```
Docker:
  mongo:7 -> :27017 (volume: mongo_data)
  backend (Python 3.11 + nmap/nikto) -> :8001
  frontend (React build + Nginx) -> :3000 -> proxy /api -> backend

Kali Host:
  msfrpcd -> :55553 (backend connects via host.docker.internal)
  sliver-server (config mounted as volume)
```

## Backlog
### P1
- [ ] Refactorizar App.js en componentes modulares

### P2
- [ ] OpSec/Evasion, BloodHound AD, multi-target campaigns
- [ ] Payload obfuscation
