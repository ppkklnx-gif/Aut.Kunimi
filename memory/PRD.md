# Red Team Framework v5.0 - PRD

## Architecture
Hybrid: Frontend+MongoDB in Docker, Backend+MSF+Sliver on Kali host.

## Implemented
- Docker: mongo:7 (volume persistent) + frontend (React+Nginx)
- Kali host: FastAPI backend, msfrpcd, sliver, nmap, nikto
- Nginx proxies /api to host.docker.internal:8001
- start.sh / stop.sh for one-command operation
- 9-section APT-style Cyberpunk UI
- Payload generator (11 templates) with global LHOST injection
- C2 resilience (MSF RPC + Sliver) with diagnostics and auto-reconnect
- Health check endpoint with connectivity diagnostics
- Adaptive scan orchestration, attack chains, credential vault

## Backlog
### P1
- Refactorizar App.js en componentes modulares

### P2
- OpSec/Evasion, BloodHound AD, multi-target, payload obfuscation
