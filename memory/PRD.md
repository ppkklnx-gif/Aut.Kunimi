# Kali Pentesting Automation Suite v2.0 - PRD

## Original Problem Statement
Herramienta web de pentesting automatizado para Kali Linux con:
- Flujo: Target → WAF → Nmap → Nikto → IA Kimi K2 → Metasploit
- Mapa/diagrama de auditoría visual con ramas para cada vulnerabilidad
- Integración Metasploit para validar y explotar vulnerabilidades
- Interfaz Matrix/Cyberpunk

## Architecture
- **Frontend**: React + TailwindCSS (Matrix theme)
- **Backend**: FastAPI + MongoDB
- **AI**: Kimi K2 (Moonshot AI) para análisis de vulnerabilidades
- **Tools**: wafw00f, nmap, nikto, whatweb, subfinder, sn1per (simulados)
- **Exploitation**: Metasploit Framework (simulado con comandos RC válidos)

## What's Been Implemented (Jan 2026)

### Core Features
- [x] Input de target (IP/URL)
- [x] 6 herramientas de pentesting seleccionables
- [x] Escaneo automatizado en background
- [x] Análisis IA con Kimi K2
- [x] **NUEVO: Mapa de auditoría visual (Attack Tree)**
  - Nodos para servicios, vulnerabilidades, exploits
  - Estados: pending, testing, verified, success, failed
  - Interacción para marcar progreso
- [x] **NUEVO: Consola Metasploit integrada**
  - 17 módulos de exploits/auxiliary
  - Búsqueda de módulos
  - Ejecución con comandos RC
- [x] Historial de escaneos con MongoDB
- [x] Exportación de reportes JSON
- [x] Interfaz Matrix/Cyberpunk completa

### API Endpoints
- POST /api/scan/start - Iniciar escaneo
- GET /api/scan/{id}/status - Estado + árbol de ataque
- GET /api/scan/{id}/tree - Árbol de ataque completo
- PUT /api/scan/{id}/tree/node/{id} - Actualizar estado de nodo
- POST /api/metasploit/execute - Ejecutar exploit
- GET /api/metasploit/modules - Buscar módulos MSF

## Prioritized Backlog
### P0 - Completado
- ✅ Core scanning workflow
- ✅ AI analysis integration
- ✅ Attack tree visualization
- ✅ Metasploit integration

### P1 (High)
- [ ] Instalar herramientas reales en Kali Linux
- [ ] Conexión real con msfrpcd
- [ ] Exportar reportes en PDF

### P2 (Medium)
- [ ] SQLmap automation avanzada
- [ ] Notificaciones WebSocket tiempo real
- [ ] Dashboard de métricas

## Next Tasks
1. Desplegar en Kali Linux real con herramientas instaladas
2. Configurar msfrpcd para ejecución real de Metasploit
3. Agregar más módulos de Metasploit
