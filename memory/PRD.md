# Red Team Automation Framework v3.2 - PRD

## Problem Statement
Framework Red Team profesional con MITRE ATT&CK, Tactical Decision Engine adaptativo, Moonshot AI (Kimi K2), Attack Chains automatizadas con motor de ejecucion, modulos MSF recomendados por relevancia, reportes PDF informales, y auto-sugerencia de cadenas.

## What's Implemented (Feb 2026)

### Core Features
- [x] 14 tacticas MITRE ATT&CK seleccionables (Kill Chain)
- [x] 10 herramientas Red Team categorizadas
- [x] 11 modulos Metasploit con MITRE mapping
- [x] Tema Matrix/Cyberpunk (#FF003C, #00FF41, negro)
- [x] Moonshot AI (Kimi K2) Red Team Advisor
- [x] Scan system con background tasks y polling

### Tactical Decision Engine
- [x] WAF bypass strategies (Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity)
- [x] Service-to-attack mapping (10+ servicios)
- [x] Vulnerability-to-exploit mapping
- [x] Adaptive planning en tiempo real

### Attack Chains
- [x] 6 cadenas predefinidas
- [x] Motor de ejecucion automatica con tracking paso a paso
- [x] Ejecucion manual paso a paso con botones [RUN]
- [x] Pipeline visual de progreso
- [x] Auto-sugerencia basada en hallazgos del escaneo

### Smart Exploits
- [x] Modulos MSF recomendados por score de relevancia
- [x] Scoring basado en servicios/vulnerabilidades detectados
- [x] Todos los modulos disponibles como referencia extra

### Reports
- [x] JSON report download
- [x] PDF report download (estilo informal entre colegas)
- [x] PDF incluye: resultados, analisis tactico, IA, cadenas sugeridas, modulos recomendados

## Architecture
- Frontend: React + TailwindCSS + Shadcn UI
- Backend: FastAPI + Motor (MongoDB async)
- Database: MongoDB
- AI: Moonshot AI (Kimi K2)
- PDF: fpdf2

## Prioritized Backlog

### P2 (Proximo)
- [ ] C2 Framework integration (Sliver/Havoc)
- [ ] WebSocket real-time updates
- [ ] Real Metasploit integration (msfrpcd)
- [ ] BloodHound AD attack paths

### P3 (Futuro)
- [ ] Multi-target campaign management
- [ ] User authentication
- [ ] Cobalt Strike Beacon simulation
