# Kali Pentesting Automation Suite - PRD

## Original Problem Statement
Crear una herramienta web para Kali Linux que automatice pentesting con flujo: Target → WAF Detection → Nmap → Sn1per → Kimi AI Analysis → Metasploit suggestions. Interfaz Matrix/Cyberpunk.

## Architecture
- **Frontend**: React + TailwindCSS con estilo Matrix/Cyberpunk
- **Backend**: FastAPI + MongoDB
- **AI**: Kimi K2 (Moonshot AI) para análisis de vulnerabilidades
- **Tools**: wafw00f, nmap, nikto, whatweb, subfinder, sn1per (simulados)

## User Personas
1. **Pentester profesional**: Automatiza flujos de reconocimiento
2. **Estudiante de ciberseguridad**: Aprende con flujos guiados por IA

## Core Requirements
- [x] Input de target (IP/URL)
- [x] Selección de herramientas de pentesting
- [x] Escaneo automatizado secuencial
- [x] Análisis de IA con Kimi K2
- [x] Sugerencias de Metasploit/SQLmap
- [x] Historial de escaneos
- [x] Exportación de reportes JSON
- [x] Interfaz Matrix/Cyberpunk

## What's Been Implemented (Jan 2026)
- Full-stack pentesting automation suite
- 6 herramientas: WAF, Nmap, Nikto, WhatWeb, Subfinder, Sn1per
- Integración Kimi K2 para análisis de vulnerabilidades
- Terminal output con ASCII art
- Tabs: Herramientas, KIMI AI, Historial
- MongoDB para persistencia
- Background tasks para escaneos

## Prioritized Backlog
### P0 (Critical)
- ✅ Core scanning workflow
- ✅ AI analysis integration

### P1 (High)
- [ ] Instalar herramientas reales en Kali Linux
- [ ] Exportar reportes en PDF
- [ ] Notificaciones en tiempo real (WebSocket)

### P2 (Medium)
- [ ] Integración con Metasploit RPC
- [ ] SQLmap automation
- [ ] Dashboard de métricas

## Next Tasks
1. Probar en entorno Kali Linux real con herramientas instaladas
2. Agregar más parsers de output para cada herramienta
3. Implementar exportación PDF
