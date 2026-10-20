# Mini Enterprise Defensive SOC Dashboard

- `soc_backend.py`: Production-grade Flask API, SQLite schema, MITRE ATT&CK correlation, and incident management.
- `agent_remediator.py`: Constrained nftables block/unblock poller; defaults to dry-run.
- `dashboard_component.html/.js/.css`: Interactive MITRE ATT&CK matrix and incident console UI.
- `nftables.conf`: Host firewall template for CN-Server (`192.168.31.91`).
- `wheels/`: Complete offline wheel distribution for Python 3.12 (Flask, Requests, python-dotenv, and dependencies).
- `test_soc_backend.py`: 22-part focused verification test suite.

## Architecture & Network Configuration

- **Secure-Dashboard VM**: `192.168.31.73`
- **CN-Server (Secure Portal)**: `192.168.31.91`
- **Dashboard API Protocol & Port**: HTTP on port `8443` (`http://192.168.31.73:8443`)
- **Event Ingestion Route**: `POST http://192.168.31.73:8443/api/events`
- **Health Check Route**: `GET http://192.168.31.73:8443/api/health`

## Environment Configuration (.env)

The following environment variables configure the dashboard (sample template in `.env.example`):
- `SOC_BIND_HOST`: Bind address (`0.0.0.0` to permit remote portal access; default: `0.0.0.0`)
- `SOC_PORT`: Listener port (default: `8443`)
- `SOC_DB_PATH`: Path to SQLite telemetry database (default: `./soc_telemetry.db`)
- `SOC_AGENT_TOKEN` (or `SOC_API_KEY`): Secret token required to ingest security telemetry via `/api/events`
- `ANALYST_TOKEN`: Secret token required for dashboard analyst actions (`/api/soc/*`)
- `SOC_BASE_URL`: Base URL for remediation poller (e.g. `http://192.168.31.73:8443`)
- `SOC_POLL_SECONDS`: Poller interval (minimum 2s)
- `SOAR_DRY_RUN`: Safe firewall mode (`true` prevents direct rule modification)

*Never commit `.env` or print secret tokens.*

## Offline Deployment Procedure on Secure-Dashboard Linux VM

Because the project resides in a VirtualBox shared folder (where symlinks fail with `Operation not permitted`), the virtual environment is maintained in `/home/socadmin/soc-venv`.

### Method 1: Offline Wheel Installation (Recommended)
Inside `/home/socadmin/soc-venv`, install all packages completely offline using the pre-bundled wheels:
```bash
# 1. Activate your local virtual environment
source /home/socadmin/soc-venv/bin/activate

# 2. Navigate to the shared folder mount (e.g. /media/sf_mini_enterprise_defensive_soc)
cd /media/sf_mini_enterprise_defensive_soc

# 3. Install requirements using the bundled offline wheels (no internet required)
pip install --no-index --find-links=./wheels -r requirements.txt
```

### Method 2: System Site-Packages (If Debian/Ubuntu packages are present)
If `python3-flask`, `python3-requests`, and `python3-dotenv` are installed system-wide:
```bash
# Enable system packages in pyvenv.cfg
sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' /home/socadmin/soc-venv/pyvenv.cfg
```

## Running the Dashboard

On the Secure-Dashboard VM (`192.168.31.73`):
```bash
source /home/socadmin/soc-venv/bin/activate
cd /media/sf_mini_enterprise_defensive_soc
python soc_backend.py
```

Startup output verifies listener and active database:
```
[*] Starting Mini Enterprise Defensive SOC Dashboard on http://0.0.0.0:8443 (HTTP)
[*] Telemetry ingestion route: http://0.0.0.0:8443/api/events
[*] MITRE matrix route: http://0.0.0.0:8443/api/soc/mitre-matrix
[*] Active database: /media/sf_mini_enterprise_defensive_soc/soc_telemetry.db
[*] Agent authentication: CONFIGURED (48 chars)
[*] Analyst authentication: CONFIGURED (48 chars)
```

## Verifying Reachability and Testing API from CN-Server

From CN-Server (`192.168.31.91`):

1. **Verify Health Endpoint (Unauthenticated):**
```bash
curl -i http://192.168.31.73:8443/api/health
```
Expected response: `HTTP/1.1 200 OK` with `{"status":"ok","timestamp":"..."}`.

2. **Verify Telemetry Ingestion (Authenticated with Agent Token):**
```bash
curl -i -X POST http://192.168.31.73:8443/api/events \
  -H "Authorization: Bearer <CONFIGURED_SOC_AGENT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"192.168.31.91","signature":"PORT_SCAN","severity":"info","message":"Port probe verification"}'
```
Expected response: `HTTP/1.1 202 Accepted` with `{"status":"accepted","event_id":"...","incident_id":...}`.

3. **Verify Invalid Token Rejection:**
```bash
curl -i -X POST http://192.168.31.73:8443/api/events \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"192.168.31.91","signature":"PORT_SCAN"}'
```
Expected response: `HTTP/1.1 401 Unauthorized`.

## Running the Test Suite

```bash
python -m unittest test_soc_backend.py
```
Covers all 22 verification categories including offline configuration validation, MITRE ATT&CK mapping, and complete SOAR lifecycle.

