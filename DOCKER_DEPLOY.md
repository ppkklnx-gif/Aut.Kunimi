# Red Team Framework v5.0 — Docker Deployment

## Requisitos

- Docker Engine 20.10+
- Docker Compose v2+
- **Kali Linux** como host (para msfrpcd, sliver, herramientas ofensivas)

```bash
# Verificar
docker --version
docker compose version
```

---

## Despliegue (3 pasos)

### 1. Configurar variables de entorno

```bash
cp .env.docker .env
nano .env
```

Edita estos valores:

```env
# Tu API key de Moonshot/Kimi
KIMI_API_KEY=sk-xxxxxxxxxxxx

# IP de tu VPS/listener (se inyecta en TODOS los payloads)
LISTENER_IP=10.10.14.5
LISTENER_PORT=4444

# Token de msfrpcd (el password que usas con msfrpcd -P)
MSF_RPC_TOKEN=tu_token_aqui

# host.docker.internal = conecta automaticamente al Kali host
MSF_RPC_HOST=host.docker.internal
MSF_RPC_PORT=55553
```

### 2. Levantar todo

```bash
docker compose up -d
```

Eso es todo. Mongo, backend y frontend se levantan automáticamente.

### 3. Abrir en navegador

```
http://localhost:3000
```

---

## Arquitectura

```
┌─────────────────── Docker ────────────────────┐
│                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ Frontend  │  │ Backend  │  │   MongoDB    ││
│  │ (Nginx)   │  │ (FastAPI)│  │   (Mongo 7)  ││
│  │ :80       │→│ :8001    │→│  :27017      ││
│  └──────────┘  └────┬─────┘  └──────────────┘│
│                      │                         │
└──────────────────────│─────────────────────────┘
                       │ host.docker.internal
┌──────────────────────│─── Kali Host ──────────┐
│                      ↓                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ msfrpcd  │  │ sliver   │  │ nmap/nikto   ││
│  │ :55553   │  │ server   │  │ herramientas ││
│  └──────────┘  └──────────┘  └──────────────┘│
└────────────────────────────────────────────────┘
```

**Frontend (Nginx):** Sirve la app React compilada y hace proxy de `/api/*` al backend.

**Backend (FastAPI):** Ejecuta escaneos, se conecta a Mongo, MSF RPC y Sliver.
Incluye nmap, nikto y gobuster dentro del contenedor.

**MongoDB:** Base de datos para scans, configs, credentials. Volumen persistente.

**Kali Host:** msfrpcd, sliver-server y herramientas pesadas que corren nativamente.

---

## Conectar MSF RPC (en Kali host)

```bash
# 1. Iniciar msfrpcd en tu Kali (escuchando en todas las interfaces)
msfrpcd -P tu_token_aqui -S -a 0.0.0.0 -p 55553

# 2. Verificar que el backend lo detecta
curl http://localhost:8001/api/health | python3 -m json.tool

# 3. En la UI: ir a C2 > deberia mostrar ONLINE
```

**Nota:** `host.docker.internal` resuelve automáticamente a la IP del host Kali.
Si usas una VPS remota para msfrpcd, cambia `MSF_RPC_HOST` a la IP de la VPS.

---

## Conectar Sliver C2 (en Kali host)

```bash
# 1. Iniciar sliver server
sliver-server &

# 2. Generar config de operador (si no existe)
# Dentro de la consola Sliver:
new-operator --name redteam --lhost 127.0.0.1 --save /home/TU_USER/.sliver-client/configs/default.cfg

# 3. Copiar el config al volumen Docker
docker cp /home/TU_USER/.sliver-client/configs/default.cfg redteam-backend:/configs/default.cfg

# 4. O montar directamente en docker-compose.yml:
#    volumes:
#      - /home/TU_USER/.sliver-client/configs:/configs:ro
```

---

## Comandos útiles

```bash
# Ver logs en tiempo real
docker compose logs -f

# Solo backend
docker compose logs -f backend

# Reiniciar un servicio
docker compose restart backend

# Reconstruir después de cambios en código
docker compose up -d --build

# Parar todo
docker compose down

# Parar y borrar datos (MongoDB incluido)
docker compose down -v

# Ver estado
docker compose ps

# Entrar al backend para debug
docker compose exec backend bash

# Ver health check
curl -s http://localhost:8001/api/health | python3 -m json.tool

# Test rápido
curl -s http://localhost:8001/api/config
curl -s http://localhost:8001/api/payloads/templates
```

---

## Verificación de conectividad

Después de `docker compose up -d`:

```bash
# 1. Verificar que todo corre
docker compose ps

# 2. Health check completo
curl -s http://localhost:8001/api/health | python3 -m json.tool
# Debes ver:
#   mongodb: connected
#   msf_rpc: connected (si msfrpcd está corriendo)
#   listener: configured (si pusiste LISTENER_IP en .env)

# 3. Frontend accesible
curl -s http://localhost:3000 | head -5

# 4. API a través de Nginx (misma ruta que usa el frontend)
curl -s http://localhost:3000/api/ | python3 -m json.tool
```

---

## Configuración del Listener (VPS)

Dos opciones:

### Opción A: Vía .env (pre-configurado)
```env
LISTENER_IP=10.10.14.5
LISTENER_PORT=4444
```
Se carga al iniciar. Persistido en MongoDB.

### Opción B: Vía la UI
1. Ir a **Config** en la app
2. Escribir la IP y puerto
3. Click **SAVE CONFIG**

Ambas opciones persisten en MongoDB. La UI siempre tiene la última configuración.

---

## Montar Sliver config desde host

Edita `docker-compose.yml`, reemplaza el volumen `sliver_configs` por un bind mount:

```yaml
backend:
  volumes:
    - /home/TU_USER/.sliver-client/configs:/configs:ro
```

---

## Troubleshooting

### Backend no conecta a MongoDB
```bash
docker compose logs mongo          # Ver logs de Mongo
docker compose exec backend python3 -c "from pymongo import MongoClient; c=MongoClient('mongodb://mongo:27017'); print(c.server_info())"
```

### Backend no conecta a msfrpcd
```bash
# Desde dentro del backend
docker compose exec backend python3 -c "import socket; s=socket.socket(); s.settimeout(3); print(s.connect_ex(('host.docker.internal', 55553)))"
# 0 = puerto abierto, otro = cerrado

# Si no funciona host.docker.internal, usa la IP de tu Kali:
ip addr show | grep 'inet ' | grep -v 127.0.0.1
# Y pon esa IP en MSF_RPC_HOST en .env
```

### Frontend muestra página en blanco
```bash
docker compose logs frontend       # Ver logs de Nginx
docker compose exec frontend ls /usr/share/nginx/html/  # Verificar build
```

### Rebuildar todo desde cero
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```
