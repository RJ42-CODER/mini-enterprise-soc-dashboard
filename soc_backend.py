"""Starter Flask SOC API with SQLite, response actions, MITRE aggregation, and Incident Investigation."""
import ipaddress, json, os, secrets, sqlite3, threading, time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List, Set
from flask import Flask, jsonify, request, render_template

def _load_env_file():
    """Load environment variables from project root .env file if present."""
    env_path = Path(__file__).resolve().with_name(".env")
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return
    except ImportError:
        pass
    # Robust fallback parser if python-dotenv is not installed
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                # Strip inline comments if not enclosed in quotes
                if not (v.startswith('"') and v.endswith('"')) and not (v.startswith("'") and v.endswith("'")):
                    v = v.split("#")[0].strip()
                v = v.strip("'\"")
                if k and (k not in os.environ or not os.environ[k]):
                    os.environ[k] = v

_load_env_file()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["TEMPLATES_AUTO_RELOAD"] = True

def get_db_path():
    """Return resolved absolute path to the SQLite telemetry database."""
    if "SOC_DB_PATH" in app.config and app.config["SOC_DB_PATH"]:
        return str(Path(app.config["SOC_DB_PATH"]).resolve())
    raw = os.getenv("SOC_DB_PATH")
    if raw:
        return str(Path(raw).resolve())
    return str(Path(__file__).resolve().with_name("soc_telemetry.db"))

def get_agent_token():
    """Return configured agent ingestion token (accepts SOC_AGENT_TOKEN or SOC_API_KEY)."""
    return (
        app.config.get("SOC_AGENT_TOKEN")
        or os.getenv("SOC_AGENT_TOKEN")
        or os.getenv("SOC_API_KEY")
        or ""
    )

def get_analyst_token():
    """Return configured analyst token for dashboard API access."""
    return app.config.get("ANALYST_TOKEN") or os.getenv("ANALYST_TOKEN") or ""

def get_bind_host():
    """Return configured bind host for Flask listener (default: 0.0.0.0)."""
    return app.config.get("SOC_BIND_HOST") or os.getenv("SOC_BIND_HOST", "0.0.0.0")

def get_port():
    """Return configured port for Flask listener (default: 8443)."""
    val = app.config.get("SOC_PORT") or os.getenv("SOC_PORT", "8443")
    try:
        p = int(val)
        if 1 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    return 8443

def get_dir_fuzz_threshold() -> int:
    """Return configured distinct 404 path threshold for DIR_FUZZ detection (default: 3)."""
    val = app.config.get("DIR_FUZZ_THRESHOLD") or os.getenv("DIR_FUZZ_THRESHOLD", "3")
    try:
        t = int(val)
        if t >= 1:
            return t
    except (ValueError, TypeError):
        pass
    return 3

def get_dir_fuzz_window() -> int:
    """Return configured sliding time window in seconds for DIR_FUZZ probe tracking (default: 60)."""
    val = app.config.get("DIR_FUZZ_WINDOW_SECONDS") or os.getenv("DIR_FUZZ_WINDOW_SECONDS", "60")
    try:
        w = int(val)
        if w >= 1:
            return w
    except (ValueError, TypeError):
        pass
    return 60

# ---------------------------------------------------------------------------
# Directory Discovery (DIR_FUZZ) Classification & Tracking Engine
# ---------------------------------------------------------------------------

BENIGN_PATHS = {
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
}

BENIGN_PREFIXES = (
    "/static/",
    "/assets/",
)

def is_benign_path(path: str) -> bool:
    """Check if requested path is a standard benign web asset (false-positive safeguard)."""
    if not path or not isinstance(path, str):
        return False
    clean = path.split("?")[0].split("#")[0].strip().lower()
    if not clean.startswith("/"):
        clean = "/" + clean
    if clean in BENIGN_PATHS:
        return True
    if any(clean.startswith(prefix) for prefix in BENIGN_PREFIXES):
        return True
    return False

SUSPICIOUS_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.save",
    "/.git", "/.git/config", "/.git/head", "/.gitignore",
    "/.svn", "/.svn/entries",
    "/.htaccess", "/.htpasswd",
    "/web.config",
    "/.aws/credentials", "/.aws/config",
    "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/authorized_keys",
    "/.bash_history", "/.bashrc",
    "/admin", "/admin/", "/admin/login",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/administrator", "/administrator/",
    "/phpmyadmin", "/phpmyadmin/", "/pma",
    "/cpanel",
    "/actuator", "/actuator/env", "/actuator/health",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/backup", "/backups", "/backup.sql", "/dump.sql",
    "/server-status", "/server-info",
}

SUSPICIOUS_EXTENSIONS = (
    ".bak", ".backup", ".old", ".orig", ".save",
    ".sql", ".tar", ".tar.gz", ".tgz", ".zip", ".dump"
)

def check_explicit_suspicious_path(path: str) -> Optional[str]:
    """Check if requested path targets known sensitive files or discovery endpoints."""
    if not path or not isinstance(path, str):
        return None
    clean = path.split("?")[0].split("#")[0].strip().lower()
    if not clean.startswith("/"):
        clean = "/" + clean
    clean_no_slash = clean.rstrip("/") if len(clean) > 1 else clean

    if clean in SUSPICIOUS_PATHS or clean_no_slash in SUSPICIOUS_PATHS:
        return f"Explicit sensitive discovery target: {clean}"

    for ext in SUSPICIOUS_EXTENSIONS:
        if clean.endswith(ext):
            return f"Suspicious backup/dump extension ({ext}): {clean}"

    if ".." in clean:
        return f"Directory traversal probe sequence: {clean}"

    return None

def get_dir_fuzz_max_sources() -> int:
    """Return configured maximum tracked source IPs in memory (default: 1000)."""
    val = app.config.get("DIR_FUZZ_MAX_SOURCES") or os.getenv("DIR_FUZZ_MAX_SOURCES", "1000")
    try:
        m = int(val)
        if m >= 1:
            return m
    except (ValueError, TypeError):
        pass
    return 1000

class DirectoryProbeTracker:
    """Thread-safe sliding-window tracker for repeated distinct path 404 probes per source IP."""
    def __init__(self):
        self._lock = threading.Lock()
        self._probes: Dict[str, List[Tuple[float, str]]] = {}
        self._seen_events: Dict[str, float] = {}

    def record_probe(
        self,
        source_ip: str,
        path: str,
        threshold: int,
        window_seconds: int,
        event_id: Optional[str] = None,
        current_time: Optional[float] = None,
        max_sources: Optional[int] = None
    ) -> Tuple[bool, int, str]:
        now_ts = time.time() if current_time is None else float(current_time)
        clean_path = (path or "").split("?")[0].split("#")[0].strip().lower()
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        max_src = max_sources or get_dir_fuzz_max_sources()

        with self._lock:
            cutoff = now_ts - window_seconds
            # Prune expired seen events
            self._seen_events = {eid: ts for eid, ts in self._seen_events.items() if ts >= cutoff}

            # Check if this exact event_id was already tracked for probes
            if event_id and str(event_id) in self._seen_events:
                history = self._probes.get(source_ip, [])
                valid_history = [(ts, p) for ts, p in history if ts >= cutoff]
                distinct_paths = {p for _, p in valid_history}
                count = len(distinct_paths)
                is_attack = count >= threshold
                reason = "Duplicate event_id already tracked"
                return is_attack, count, reason

            if event_id:
                self._seen_events[str(event_id)] = now_ts

            # Capacity limit & LRU pruning for source IPs
            history = self._probes.get(source_ip, [])
            valid_history = [(ts, p) for ts, p in history if ts >= cutoff]

            if source_ip not in self._probes and len(self._probes) >= max_src:
                stale_ips = [ip for ip, hist in self._probes.items() if not any(ts >= cutoff for ts, _ in hist)]
                for sip in stale_ips:
                    del self._probes[sip]
                if len(self._probes) >= max_src:
                    oldest_ip = min(self._probes.keys(), key=lambda k: max((t for t, _ in self._probes[k]), default=0))
                    del self._probes[oldest_ip]

            valid_history.append((now_ts, clean_path))
            self._probes[source_ip] = valid_history

            distinct_paths = {p for _, p in valid_history}
            count = len(distinct_paths)

            if count >= threshold:
                sample = ", ".join(sorted(distinct_paths)[:4])
                reason = f"Threshold exceeded: {count} distinct 404 path probes within {window_seconds}s (probed: {sample})"
                return True, count, reason
            else:
                reason = f"Below threshold: {count}/{threshold} distinct path probes within {window_seconds}s"
                return False, count, reason

    def clear(self):
        with self._lock:
            self._probes.clear()
            self._seen_events.clear()

probe_tracker = DirectoryProbeTracker()

def reset_dir_fuzz_tracker():
    """Reset the directory probe tracker state (used for testing and lifecycle resets)."""
    probe_tracker.clear()

def validate_startup_config():
    """
    Validate server configuration on startup.
    Ensures required secrets and parameters exist without exposing sensitive token values.
    Returns a dict of sanitized configuration status info or raises SystemExit.
    """
    errors = []
    agent_tok = get_agent_token()
    analyst_tok = get_analyst_token()

    if not agent_tok:
        errors.append("Missing agent authentication token: Set SOC_AGENT_TOKEN (or SOC_API_KEY) in .env or environment.")
    elif agent_tok.startswith("replace_with_"):
        errors.append("Placeholder agent token detected: Replace placeholder in .env with your actual random secret.")

    if not analyst_tok:
        errors.append("Missing analyst authentication token: Set ANALYST_TOKEN in .env or environment.")
    elif analyst_tok.startswith("replace_with_"):
        errors.append("Placeholder analyst token detected: Replace placeholder in .env with your actual random secret.")

    raw_port = app.config.get("SOC_PORT") or os.getenv("SOC_PORT", "8443")
    try:
        port = int(raw_port)
        if not (1 <= port <= 65535):
            errors.append(f"Invalid SOC_PORT '{port}': Port must be an integer between 1 and 65535.")
    except (ValueError, TypeError):
        errors.append(f"Invalid SOC_PORT '{raw_port}': Port must be a numeric integer.")
        port = 8443

    db_path = Path(get_db_path())
    db_dir = db_path.parent
    if not db_dir.exists():
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Database directory '{db_dir}' cannot be created: {str(e)}")
    elif not os.access(db_dir, os.W_OK):
        errors.append(f"Database directory '{db_dir}' is not writable. Check folder permissions.")

    if errors:
        msg = "\n".join(f"  [!] {e}" for e in errors)
        raise SystemExit(
            f"=== SOC Dashboard Startup Configuration Error ===\n"
            f"{msg}\n"
            f"Please verify settings in .env before starting the dashboard.\n"
            f"=================================================="
        )

    bind_host = get_bind_host()
    return {
        "bind_host": bind_host,
        "port": port,
        "db_path": str(db_path),
        "agent_auth_configured": bool(agent_tok),
        "agent_token_len": len(agent_tok),
        "analyst_auth_configured": bool(analyst_tok),
        "analyst_token_len": len(analyst_tok),
    }

# 6 Core MITRE ATT&CK Mappings
REGISTRY = {
 "PORT_SCAN": ("T1046", "Network Service Discovery", "Reconnaissance"),
 "DIR_FUZZ": ("T1083", "File and Directory Discovery", "Discovery"),
 "PATH_TRAVERSAL": ("T1083", "File and Directory Discovery", "Discovery"),
 "SQL_INJECTION": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
 "BRUTE_FORCE_AUTH": ("T1110", "Brute Force", "Credential Access"),
 "COMMAND_INJECTION": ("T1059", "Command and Scripting Interpreter", "Execution"),
}

# Canonical normalization for website agent & detector event types
EVENT_NORMALIZATION = {
    # PORT_SCAN
    "PORT_SCAN": "PORT_SCAN",
    "PORTSCAN": "PORT_SCAN",
    "PORT_SCANNING": "PORT_SCAN",
    "PORT-SCAN": "PORT_SCAN",
    # DIR_FUZZ
    "DIR_FUZZ": "DIR_FUZZ",
    "DIR_FUZZING": "DIR_FUZZ",
    "DIRECTORY_FUZZ": "DIR_FUZZ",
    "DIRECTORY_FUZZING": "DIR_FUZZ",
    "DIRECTORY_BRUTEFORCE": "DIR_FUZZ",
    "DIR-FUZZ": "DIR_FUZZ",
    "DIRECTORY_DISCOVERY": "DIR_FUZZ",
    "DIR_PROBE": "DIR_FUZZ",
    "DIR_SCAN": "DIR_FUZZ",
    "DIRECTORY_SCAN": "DIR_FUZZ",
    "SUSPICIOUS_PATH": "DIR_FUZZ",
    "HTTP_404": "HTTP_404",
    "NOT_FOUND": "HTTP_404",
    "404": "HTTP_404",
    # PATH_TRAVERSAL
    "PATH_TRAVERSAL": "PATH_TRAVERSAL",
    "DIRECTORY_TRAVERSAL": "PATH_TRAVERSAL",
    "FILE_PATH_TRAVERSAL": "PATH_TRAVERSAL",
    "PATH-TRAVERSAL": "PATH_TRAVERSAL",
    # SQL_INJECTION
    "SQL_INJECTION": "SQL_INJECTION",
    "SQLI": "SQL_INJECTION",
    "SQL-INJECTION": "SQL_INJECTION",
    "SQL_INJECT": "SQL_INJECTION",
    # BRUTE_FORCE_AUTH
    "BRUTE_FORCE_AUTH": "BRUTE_FORCE_AUTH",
    "BRUTE_FORCE": "BRUTE_FORCE_AUTH",
    "AUTH_BRUTE_FORCE": "BRUTE_FORCE_AUTH",
    "LOGIN_BRUTE_FORCE": "BRUTE_FORCE_AUTH",
    "CREDENTIAL_BRUTE_FORCE": "BRUTE_FORCE_AUTH",
    "LOGIN_FAILED": "BRUTE_FORCE_AUTH",
    # COMMAND_INJECTION
    "COMMAND_INJECTION": "COMMAND_INJECTION",
    "CMD_INJECTION": "COMMAND_INJECTION",
    "OS_COMMAND_INJECTION": "COMMAND_INJECTION",
    "COMMAND-INJECTION": "COMMAND_INJECTION",
}

# Non-attack operational events (acknowledged safely without false-positive attack alerts)
NON_ATTACK_SIGNATURES = {
    "HEARTBEAT", "PING", "HEALTHCHECK", "HEALTH_CHECK", "STATUS", "AUTH_SUCCESS", "LOGIN_SUCCESS"
}

# Formal Analyst Investigation Workflow States
VALID_INCIDENT_STATUSES = (
    "NEW",
    "TRIAGE",
    "INVESTIGATING",
    "CLASSIFIED",
    "RESPONSE_REQUESTED",
    "CONTAINMENT_PENDING_APPROVAL",
    "CONTAINED",
    "CLOSED"
)

# Formal Investigation Classification Categories
VALID_CLASSIFICATIONS = (
    "CONFIRMED_MALICIOUS",
    "BENIGN_AUTHORIZED_TESTING",
    "INCONCLUSIVE"
)

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

@contextmanager
def db(db_path=None):
    target = db_path or get_db_path()
    c = sqlite3.connect(target, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()

def init_db(db_path=None):
    with db(db_path) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alerts(
          id INTEGER PRIMARY KEY, event_id TEXT UNIQUE, source_ip TEXT NOT NULL,
          signature TEXT NOT NULL, severity TEXT NOT NULL, timestamp TEXT NOT NULL,
          message TEXT NOT NULL DEFAULT '', mitre_id TEXT, incident_id INTEGER,
          http_method TEXT, requested_path TEXT, response_status INTEGER, detection_reason TEXT);
        CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON alerts(mitre_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip);

        CREATE TABLE IF NOT EXISTS response_actions(
          action_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER,
          target_ip TEXT NOT NULL, action_type TEXT NOT NULL CHECK(action_type IN ('BLOCK_IP','UNBLOCK_IP')),
          status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','EXECUTED','FAILED','CANCELLED','DRY_RUN','VERIFIED')),
          triggered_by TEXT NOT NULL CHECK(triggered_by IN ('AUTO_RULE','SOC_ANALYST')),
          created_at TEXT NOT NULL, executed_at TEXT, timeout_seconds INTEGER,
          message TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_actions_status ON response_actions(status, action_id);
        CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions(incident_id);

        CREATE TABLE IF NOT EXISTS incidents(
          incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('NEW','TRIAGE','INVESTIGATING','CLASSIFIED','RESPONSE_REQUESTED','CONTAINMENT_PENDING_APPROVAL','CONTAINED','CLOSED')) DEFAULT 'NEW',
          classification TEXT CHECK(classification IN ('CONFIRMED_MALICIOUS','BENIGN_AUTHORIZED_TESTING','INCONCLUSIVE', NULL)),
          classification_rationale TEXT NOT NULL DEFAULT '',
          severity TEXT NOT NULL DEFAULT 'medium',
          source_ip TEXT NOT NULL,
          signature TEXT NOT NULL,
          mitre_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          closed_at TEXT,
          closure_rationale TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(source_ip);
        CREATE INDEX IF NOT EXISTS idx_incidents_sig ON incidents(signature);

        CREATE TABLE IF NOT EXISTS incident_notes(
          note_id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL REFERENCES incidents(incident_id),
          author TEXT NOT NULL DEFAULT 'SOC_ANALYST',
          created_at TEXT NOT NULL,
          note_text TEXT NOT NULL,
          note_type TEXT NOT NULL DEFAULT 'ANALYST_NOTE' CHECK(note_type IN ('ANALYST_NOTE','STATUS_CHANGE','CLASSIFICATION','CONTAINMENT_REQUEST','SYSTEM'))
        );
        CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes(incident_id);

        CREATE TABLE IF NOT EXISTS reports(
          report_id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE SET NULL,
          title TEXT NOT NULL,
          report_type TEXT NOT NULL,
          summary TEXT NOT NULL,
          findings TEXT NOT NULL,
          date_range TEXT,
          author TEXT NOT NULL DEFAULT 'SOC_ANALYST',
          created_at TEXT NOT NULL,
          content_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_reports_incident ON reports(incident_id);
        """)

        # Safe migration: ensure incident_id column exists on alerts
        cols = [r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()]
        if "incident_id" not in cols:
            c.execute("ALTER TABLE alerts ADD COLUMN incident_id INTEGER REFERENCES incidents(incident_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")

        # Safe migration: ensure HTTP and detection metadata columns exist on alerts
        for col_name, col_type in [
            ("http_method", "TEXT"),
            ("requested_path", "TEXT"),
            ("response_status", "INTEGER"),
            ("detection_reason", "TEXT"),
        ]:
            if col_name not in cols:
                c.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")

        # Safe migration: link any unlinked historical alerts into incidents
        unlinked = c.execute("SELECT id, event_id, source_ip, signature, severity, timestamp, message, mitre_id FROM alerts WHERE incident_id IS NULL ORDER BY id ASC").fetchall()
        if unlinked:
            groups = {}
            for row in unlinked:
                key = (row["source_ip"], row["signature"])
                groups.setdefault(key, []).append(row)

            sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            for (sip, sig), alert_list in groups.items():
                tech_name = REGISTRY.get(sig, (None, sig, None))[1]
                mitre = REGISTRY.get(sig, (None, None, None))[0]
                earliest_ts = alert_list[0]["timestamp"]
                latest_ts = alert_list[-1]["timestamp"]
                max_sev = max(alert_list, key=lambda a: sev_rank.get(str(a["severity"]).lower(), 2))["severity"]
                title = f"{tech_name} detected from {sip}"

                cur_inc = c.execute("""
                    INSERT INTO incidents (title, status, severity, source_ip, signature, mitre_id, created_at, updated_at)
                    VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?)
                """, (title, max_sev, sip, sig, mitre, earliest_ts, latest_ts))
                inc_id = cur_inc.lastrowid

                alert_ids = [a["id"] for a in alert_list]
                c.execute(f"UPDATE alerts SET incident_id = ? WHERE id IN ({','.join('?' for _ in alert_ids)})", [inc_id] + alert_ids)

                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SYSTEM', ?, ?, 'SYSTEM')
                """, (inc_id, now(), f"Incident initialized with {len(alert_list)} existing alert(s)."))

def auth(role):
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            expected = get_agent_token() if role == "agent" else get_analyst_token()
            if not expected:
                app.logger.warning(
                    f"Authentication rejected on {request.method} {request.path}: "
                    f"{role} authentication is not configured on the SOC backend (missing token)"
                )
                return jsonify(error=f"{role} auth not configured"), 503
            header = request.headers.get("Authorization", "")
            token = header[7:].strip() if header.startswith("Bearer ") else ""
            if not token and not header:
                token = request.headers.get("X-API-Key", "").strip()
            client_ip = request.remote_addr or "unknown"
            if not token:
                app.logger.warning(
                    f"Authentication failed on {request.method} {request.path} from {client_ip}: "
                    f"Missing or malformed Authorization header (expected Bearer token)"
                )
                return jsonify(error="Unauthorized"), 401
            if not secrets.compare_digest(token, expected):
                app.logger.warning(
                    f"Authentication failed on {request.method} {request.path} from {client_ip}: "
                    f"Invalid {role} token supplied (length: {len(token)})"
                )
                return jsonify(error="Unauthorized"), 401
            return fn(*a, **kw)
        return inner
    return deco

def valid_ip(raw):
    ip = ipaddress.ip_address(raw)
    if not isinstance(ip, ipaddress.IPv4Address) or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ValueError("Expected non-special IPv4 address")
    return str(ip)

def enqueue(target, kind, actor, timeout=None, incident_id=None):
    target = valid_ip(target)
    if kind not in ("BLOCK_IP", "UNBLOCK_IP"): raise ValueError("Unsupported action")
    if timeout is not None and not 1 <= int(timeout) <= 604800: raise ValueError("Timeout must be 1 second to 7 days")
    with db() as c:
        cur = c.execute("""INSERT INTO response_actions
          (incident_id,target_ip,action_type,status,triggered_by,created_at,timeout_seconds)
          VALUES(?,?,?,'PENDING',?,?,?)""", (incident_id,target,kind,actor,now(),timeout))
        return cur.lastrowid

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health(): return jsonify(status="ok", timestamp=now())

@app.post("/api/events")
@auth("agent")
def ingest():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="JSON object body required"), 400

    if "source_ip" not in d:
        return jsonify(error="Missing required field 'source_ip'"), 400
    try:
        source = valid_ip(d["source_ip"])
    except (ValueError, TypeError) as e:
        return jsonify(error=f"Invalid 'source_ip': {str(e)}"), 400

    raw_sig = d.get("signature") or d.get("alert_type") or d.get("event_type")
    # If no explicit signature/alert_type/event_type, check response status code for 404
    if not raw_sig:
        raw_status = d.get("response_status") if "response_status" in d else (d.get("status_code") if "status_code" in d else d.get("status"))
        if str(raw_status).strip() in ("404",):
            raw_sig = "HTTP_404"

    if not raw_sig or not isinstance(raw_sig, str) or not raw_sig.strip():
        return jsonify(error="Missing required field: 'signature', 'alert_type', or 'event_type'"), 400

    cleaned_sig = raw_sig.upper().strip()

    # Acknowledge non-attack telemetry (heartbeat / ping / auth success) without false-positive alerts
    if cleaned_sig in NON_ATTACK_SIGNATURES:
        app.logger.info(f"Operational telemetry acknowledged from {source}: {cleaned_sig}")
        return jsonify(
            status="accepted",
            event_type=cleaned_sig.lower(),
            message="Operational telemetry acknowledged; no security alert recorded"
        ), 202

    # Extract HTTP telemetry fields
    http_method = str(d.get("method") or d.get("http_method") or "GET").upper().strip()[:10]
    requested_path = str(d.get("path") or d.get("url") or d.get("requested_path") or "").strip()[:512]
    try:
        raw_status = d.get("response_status") if "response_status" in d else (d.get("status_code") if "status_code" in d else d.get("status"))
        if raw_status is not None:
            parsed_status = int(raw_status)
            if 100 <= parsed_status <= 599:
                response_status = parsed_status
            else:
                response_status = None
        else:
            response_status = 404 if "404" in cleaned_sig else None
    except (ValueError, TypeError):
        response_status = None
    detection_reason = str(d.get("reason") or d.get("detection_reason") or "").strip()[:512]

    # Validate event_id format if provided
    raw_event_id = d.get("event_id")
    if raw_event_id is not None and not isinstance(raw_event_id, (str, int)):
        return jsonify(error="Field 'event_id' must be a string or integer"), 400
    event_id = str(raw_event_id or secrets.token_hex(16))[:64]

    # Early idempotency check: if event_id already exists in alerts table, return existing record
    if raw_event_id is not None:
        try:
            with db() as c:
                existing = c.execute(
                    "SELECT event_id, incident_id, mitre_id, signature FROM alerts WHERE event_id=?",
                    (event_id,)
                ).fetchone()
                if existing:
                    app.logger.info(f"Duplicate event_id '{event_id}' safely deduplicated (idempotent)")
                    return jsonify(
                        status="accepted",
                        event_id=existing["event_id"],
                        mitre_id=existing["mitre_id"],
                        signature=existing["signature"],
                        incident_id=existing["incident_id"]
                    ), 202
        except sqlite3.Error as e:
            return jsonify(error=f"Database persistence error: {str(e)}"), 500

    # Handle Directory Discovery (DIR_FUZZ) & HTTP 404 Probing Logic
    is_dir_fuzz_candidate = (
        cleaned_sig in ("HTTP_404", "NOT_FOUND", "404", "DIR_PROBE", "DIRECTORY_DISCOVERY", "SUSPICIOUS_PATH")
        or (cleaned_sig in ("DIR_FUZZ", "DIR_FUZZING", "DIRECTORY_FUZZ", "DIRECTORY_FUZZING", "DIRECTORY_BRUTEFORCE", "DIR-FUZZ") and requested_path)
    )

    if is_dir_fuzz_candidate:
        # False-positive safeguard: exclude benign assets
        if is_benign_path(requested_path):
            app.logger.info(f"Benign path probe '{requested_path}' from {source} ignored (false-positive safeguard)")
            return jsonify(
                status="accepted",
                event_type="benign_path_suppressed",
                message="Benign path probe ignored (false-positive safeguard); no security alert recorded"
            ), 202

        # 1. Immediate trigger: check explicit suspicious path
        explicit_reason = check_explicit_suspicious_path(requested_path)
        if explicit_reason:
            sig = "DIR_FUZZ"
            detection_reason = detection_reason or explicit_reason
            if "severity" not in d:
                clean_lower = requested_path.lower()
                if any(k in clean_lower for k in ("/.env", "/.git", "credentials", "id_rsa", "backup.sql")):
                    raw_sev = "high"
                else:
                    raw_sev = "medium"
            else:
                raw_sev = d.get("severity", "medium")
        elif cleaned_sig in ("HTTP_404", "NOT_FOUND", "404", "DIR_PROBE"):
            # 2. Threshold trigger: check repeated distinct 404 path probes
            threshold = get_dir_fuzz_threshold()
            window = get_dir_fuzz_window()
            is_attack, count, tracker_reason = probe_tracker.record_probe(
                source, requested_path, threshold, window, event_id=raw_event_id
            )
            if is_attack:
                sig = "DIR_FUZZ"
                detection_reason = detection_reason or tracker_reason
                raw_sev = d.get("severity", "medium")
            else:
                # Below threshold: acknowledge without attack alert
                app.logger.info(f"404 probe from {source} for '{requested_path}' below threshold ({count}/{threshold})")
                return jsonify(
                    status="accepted",
                    event_type="probe_recorded",
                    distinct_probes=count,
                    threshold=threshold,
                    message=f"Probe recorded ({count}/{threshold} in window); below threshold, no security alert recorded"
                ), 202
        else:
            # Client specified DIR_FUZZ with non-benign path
            sig = "DIR_FUZZ"
            detection_reason = detection_reason or f"Directory fuzzing probe targeting {requested_path}"
            raw_sev = d.get("severity", "medium")
    else:
        sig = EVENT_NORMALIZATION.get(cleaned_sig)
        if not sig or sig not in REGISTRY:
            app.logger.warning(f"Ingestion rejected from {source}: Unsupported signature '{raw_sig}'")
            return jsonify(
                error=f"Unsupported signature '{raw_sig}'. Must map to registered detection types: {list(REGISTRY.keys())}"
            ), 400
        raw_sev = d.get("severity", "medium")

    # Validate severity
    if not isinstance(raw_sev, str):
        return jsonify(error="Field 'severity' must be a string"), 400
    severity = raw_sev.lower().strip()
    if severity not in ("info", "low", "medium", "high", "critical"):
        app.logger.warning(f"Ingestion rejected from {source}: Invalid severity '{raw_sev}'")
        return jsonify(error=f"Invalid 'severity' '{raw_sev}'. Must be one of ('info', 'low', 'medium', 'high', 'critical')"), 400

    raw_ts = d.get("timestamp")
    if raw_ts is not None and not isinstance(raw_ts, str):
        return jsonify(error="Field 'timestamp' must be a string"), 400
    ts = str(raw_ts or now())[:64]

    raw_msg = d.get("message")
    if raw_msg is not None and not isinstance(raw_msg, str):
        return jsonify(error="Field 'message' must be a string"), 400

    # Build structured message preserving original telemetry metadata
    details = []
    if http_method: details.append(f"method={http_method}")
    if requested_path: details.append(f"path={requested_path}")
    if response_status: details.append(f"status={response_status}")
    if detection_reason: details.append(f"reason={detection_reason}")

    if raw_msg:
        msg = str(raw_msg)[:2048]
    elif details:
        msg = f"{REGISTRY[sig][1]} probe detected ({'; '.join(details)})"[:2048]
    else:
        msg = ""

    mitre = REGISTRY[sig][0]
    try:
        with db() as c:
            # 1. Insert alert with extended HTTP telemetry columns
            c.execute("""INSERT OR IGNORE INTO alerts
              (event_id,source_ip,signature,severity,timestamp,message,mitre_id,
               http_method,requested_path,response_status,detection_reason)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
              (event_id, source, sig, severity, ts, msg, mitre,
               http_method if requested_path else None,
               requested_path if requested_path else None,
               response_status,
               detection_reason if detection_reason else None))

            # 2. Correlate to existing open incident or create new incident
            inc_row = c.execute("""
                SELECT incident_id, severity FROM incidents
                WHERE source_ip = ? AND signature = ? AND status != 'CLOSED'
                ORDER BY incident_id DESC LIMIT 1
            """, (source, sig)).fetchone()

            sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if inc_row:
                inc_id = inc_row["incident_id"]
                current_inc_sev = inc_row["severity"]
                new_inc_sev = severity if sev_rank.get(severity, 2) > sev_rank.get(current_inc_sev, 2) else current_inc_sev
                c.execute("""
                    UPDATE incidents SET updated_at = ?, severity = ? WHERE incident_id = ?
                """, (now(), new_inc_sev, inc_id))
                c.execute("UPDATE alerts SET incident_id = ? WHERE event_id = ?", (inc_id, event_id))
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SYSTEM', ?, ?, 'SYSTEM')
                """, (inc_id, now(), f"Correlated alert {event_id} ({severity}): {msg[:120]}"))
                app.logger.info(f"Correlated {sig} alert ({event_id}, severity={severity}) from {source} into existing incident #{inc_id}")
            else:
                tech_name = REGISTRY[sig][1]
                title = f"{tech_name} detected from {source}"
                cur_inc = c.execute("""
                    INSERT INTO incidents (title, status, severity, source_ip, signature, mitre_id, created_at, updated_at)
                    VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?)
                """, (title, severity, source, sig, mitre, ts, now()))
                inc_id = cur_inc.lastrowid
                c.execute("UPDATE alerts SET incident_id = ? WHERE event_id = ?", (inc_id, event_id))
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SYSTEM', ?, ?, 'SYSTEM')
                """, (inc_id, now(), f"Incident opened from alert {event_id} ({severity}): {msg[:120]}"))
                app.logger.info(f"Opened new incident #{inc_id} from {sig} alert ({event_id}, severity={severity}) from {source}")

    except sqlite3.Error as e:
        return jsonify(error=f"Database persistence error: {str(e)}"), 500

    return jsonify(
        status="accepted",
        event_id=event_id,
        mitre_id=mitre,
        signature=sig,
        incident_id=inc_id
    ), 202

@app.get("/api/agent/pending-actions")
@auth("agent")
def pending():
    with db() as c:
        rows = c.execute("""SELECT action_id,target_ip,action_type AS type,timeout_seconds
          FROM response_actions WHERE status='APPROVED' ORDER BY action_id LIMIT 10""").fetchall()
    return jsonify(status="success",actions=[dict(r) for r in rows])

@app.post("/api/agent/action-status")
@auth("agent")
def status():
    d=request.get_json(silent=True) or {}
    try: aid=int(d["action_id"])
    except (KeyError,ValueError,TypeError): return jsonify(error="Valid action_id required"),400
    state=d.get("status")
    if state not in ("EXECUTED","FAILED","DRY_RUN"): return jsonify(error="Invalid status"),400
    with db() as c:
        cur=c.execute("""UPDATE response_actions SET status=?,executed_at=?,message=?
          WHERE action_id=? AND status='APPROVED'""",(state,now(),str(d.get("message",""))[:500],aid))
        if cur.rowcount != 1: return jsonify(error="Action not found or not approved"),404
    return jsonify(status="acknowledged")

@app.post("/api/soc/mitigate/block")
@auth("analyst")
def block():
    d=request.get_json(silent=True) or {}
    inc_id = d.get("incident_id")
    try:
        aid=enqueue(d["target_ip"],"BLOCK_IP","SOC_ANALYST",d.get("timeout_seconds"),inc_id)
    except (KeyError,ValueError,TypeError) as e:
        return jsonify(error=str(e)),400

    if inc_id:
        try:
            with db() as c:
                c.execute("""
                    UPDATE incidents SET status = 'CONTAINMENT_PENDING_APPROVAL', updated_at = ?
                    WHERE incident_id = ?
                """, (now(), inc_id))
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Containment BLOCK_IP action #{aid} queued for target {d['target_ip']}. Status: PENDING_APPROVAL"))
        except Exception:
            pass

    return jsonify(status="PENDING_APPROVAL",action_id=aid,incident_id=inc_id),202

@app.post("/api/soc/mitigate/unblock")
@auth("analyst")
def unblock():
    d=request.get_json(silent=True) or {}
    inc_id = d.get("incident_id")
    try:
        aid=enqueue(d["target_ip"],"UNBLOCK_IP","SOC_ANALYST",None,inc_id)
    except (KeyError,ValueError,TypeError) as e:
        return jsonify(error=str(e)),400

    if inc_id:
        try:
            with db() as c:
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Rollback UNBLOCK_IP action #{aid} queued for target {d['target_ip']}. Status: PENDING_APPROVAL"))
        except Exception:
            pass

    return jsonify(status="PENDING_APPROVAL",action_id=aid,incident_id=inc_id),202

@app.post("/api/soc/response-actions/<int:aid>/approve")
@auth("analyst")
def approve(aid):
    with db() as c:
        action = c.execute("SELECT * FROM response_actions WHERE action_id=? AND status='PENDING'", (aid,)).fetchone()
        if not action:
            return jsonify(error="Not pending or not found"), 404
        c.execute("UPDATE response_actions SET status='APPROVED' WHERE action_id=?", (aid,))
        inc_id = action["incident_id"]
        if inc_id:
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
            """, (inc_id, now(), f"Containment action #{aid} ({action['action_type']}) approved by analyst. Status: APPROVED"))
    return jsonify(status="APPROVED",action_id=aid)

@app.post("/api/soc/response-actions/<int:aid>/verify")
@auth("analyst")
def verify_action(aid):
    with db() as c:
        action = c.execute(
            "SELECT * FROM response_actions WHERE action_id=? AND status IN ('EXECUTED','APPROVED','DRY_RUN')",
            (aid,)
        ).fetchone()
        if not action:
            return jsonify(error="Action not found or not in a verifiable status (EXECUTED/APPROVED/DRY_RUN)"), 404
        c.execute("UPDATE response_actions SET status='VERIFIED' WHERE action_id=?", (aid,))
        inc_id = action["incident_id"]
        if inc_id:
            c.execute("""
                UPDATE incidents SET status = 'CONTAINED', updated_at = ? WHERE incident_id = ?
            """, (now(), inc_id))
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
            """, (inc_id, now(), f"Containment action #{aid} verified against host nftables. Status: VERIFIED. Incident transitioned to CONTAINED."))
    return jsonify(status="VERIFIED", action_id=aid)

@app.get("/api/soc/mitre-matrix")
@auth("analyst")
def matrix():
    items=[]
    with db() as c:
        for sig,(tid,name,tactic) in REGISTRY.items():
            count=c.execute("SELECT COUNT(*) FROM alerts WHERE signature=?",(sig,)).fetchone()[0]
            # VERIFIED must be set only after independent confirmation of the host nft set.
            mitigated=c.execute("""SELECT COUNT(*) FROM response_actions
              WHERE action_type='BLOCK_IP' AND status='VERIFIED'
              AND target_ip IN (SELECT source_ip FROM alerts WHERE signature=?)""",(sig,)).fetchone()[0]
            state="UNTESTED" if count==0 else ("MITIGATED" if mitigated else "DETECTED")
            items.append(dict(signature=sig,technique_id=tid,technique_name=name,tactic=tactic,
                              alert_count=count,mitigated_count=mitigated,state=state))
    detected=sum(x["alert_count"]>0 for x in items)
    mitigated=sum(x["state"]=="MITIGATED" for x in items)
    index=round(mitigated/detected*100,2) if detected else None
    return jsonify(status="success",matrix=items,resilience_index=index,
                   detected_techniques=detected,mitigated_techniques=mitigated,
                   note="MITIGATED requires independent verification; execution alone is insufficient.")

# ---------------------------------------------------------------------------
# Incident Investigation Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/soc/incidents")
@auth("analyst")
def list_incidents():
    status_filter = request.args.get("status", "").upper().strip()
    sig_filter = request.args.get("signature", "").upper().strip()
    ip_filter = request.args.get("source_ip", "").strip()

    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if status_filter:
        if status_filter == "OPEN":
            query += " AND status != 'CLOSED'"
        elif status_filter != "ALL":
            query += " AND status = ?"
            params.append(status_filter)

    if sig_filter:
        query += " AND signature = ?"
        params.append(sig_filter)

    if ip_filter:
        query += " AND source_ip = ?"
        params.append(ip_filter)

    query += " ORDER BY incident_id DESC"

    with db() as c:
        rows = c.execute(query, params).fetchall()
        incidents = []
        for r in rows:
            inc = dict(r)
            inc["id"] = inc["incident_id"]
            sig = inc["signature"]
            reg_info = REGISTRY.get(sig, (inc["mitre_id"] or "Unknown", sig, "Unknown"))
            inc["technique_id"] = reg_info[0]
            inc["technique_name"] = reg_info[1]
            inc["tactic"] = reg_info[2]

            # Count alerts
            cnt = c.execute("SELECT COUNT(*) FROM alerts WHERE incident_id = ?", (inc["incident_id"],)).fetchone()[0]
            inc["alert_count"] = cnt

            # Check latest action status
            act = c.execute("""
                SELECT action_id, action_type, status FROM response_actions
                WHERE incident_id = ? OR target_ip = ?
                ORDER BY action_id DESC LIMIT 1
            """, (inc["incident_id"], inc["source_ip"])).fetchone()
            inc["latest_action"] = dict(act) if act else None

            incidents.append(inc)

    return jsonify(status="success", count=len(incidents), incidents=incidents)

@app.get("/api/soc/incidents/<int:incident_id>")
@auth("analyst")
def get_incident_details(incident_id):
    with db() as c:
        inc_row = c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not inc_row:
            return jsonify(error="Incident not found"), 404

        inc = dict(inc_row)
        inc["id"] = inc["incident_id"]
        sig = inc["signature"]
        reg_info = REGISTRY.get(sig, (inc["mitre_id"] or "Unknown", sig, "Unknown"))
        inc["technique_id"] = reg_info[0]
        inc["technique_name"] = reg_info[1]
        inc["tactic"] = reg_info[2]

        # Primary and linked alerts
        alert_rows = c.execute("""
            SELECT id, event_id, source_ip, signature, severity, timestamp, message, mitre_id,
                   http_method, requested_path, response_status, detection_reason
            FROM alerts WHERE incident_id = ? ORDER BY id DESC
        """, (incident_id,)).fetchall()
        alerts = [dict(a) for a in alert_rows]

        # Related alerts (same source_ip or signature from other incidents or unlinked)
        related_rows = c.execute("""
            SELECT id, event_id, source_ip, signature, severity, timestamp, message, mitre_id, incident_id,
                   http_method, requested_path, response_status, detection_reason
            FROM alerts
            WHERE (source_ip = ? OR signature = ?) AND (incident_id IS NULL OR incident_id != ?)
            ORDER BY id DESC LIMIT 15
        """, (inc["source_ip"], sig, incident_id)).fetchall()
        related_alerts = [dict(r) for r in related_rows]

        # Response actions
        action_rows = c.execute("""
            SELECT action_id, incident_id, target_ip, action_type, status, triggered_by, created_at, executed_at, timeout_seconds, message
            FROM response_actions
            WHERE incident_id = ? OR target_ip = ?
            ORDER BY action_id DESC
        """, (incident_id, inc["source_ip"])).fetchall()
        actions = [dict(a) for a in action_rows]

        # Notes and audit log
        note_rows = c.execute("""
            SELECT note_id, incident_id, author, created_at, note_text, note_type
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY note_id ASC
        """, (incident_id,)).fetchall()
        notes = []
        for r in note_rows:
            nd = dict(r)
            nd["note"] = nd["note_text"]
            notes.append(nd)

        # Build combined chronological timeline
        timeline = []
        for a in alerts:
            timeline.append({
                "type": "ALERT",
                "timestamp": a["timestamp"],
                "title": f"Alert Ingested ({a['event_id']})",
                "detail": a["message"] or f"Signature {a['signature']} detected",
                "severity": a["severity"],
                "extra": a
            })
        for act in actions:
            timeline.append({
                "type": "RESPONSE_ACTION",
                "timestamp": act["executed_at"] or act["created_at"],
                "title": f"Response Action #{act['action_id']} ({act['action_type']})",
                "detail": f"Status: {act['status']} (Triggered by {act['triggered_by']})",
                "status": act["status"],
                "extra": act
            })
        for n in notes:
            timeline.append({
                "type": "NOTE" if n["note_type"] == "ANALYST_NOTE" else "AUDIT",
                "timestamp": n["created_at"],
                "title": f"Note by {n['author']}" if n["note_type"] == "ANALYST_NOTE" else f"Audit: {n['note_type']}",
                "detail": n["note_text"],
                "extra": n
            })

        # Sort timeline chronologically (earliest to latest)
        timeline.sort(key=lambda x: str(x["timestamp"]))

        # Populate convenience fields on inc
        inc["correlated_alerts"] = alerts
        inc["related_alerts"] = related_alerts
        inc["response_actions"] = actions
        inc["notes"] = notes
        inc["timeline"] = timeline

        return jsonify(
            status="success",
            incident=inc,
            alerts=alerts,
            related_alerts=related_alerts,
            response_actions=actions,
            notes=notes,
            timeline=timeline
        )

@app.post("/api/soc/incidents/<int:incident_id>/status")
@auth("analyst")
def update_incident_status(incident_id):
    d = request.get_json(silent=True) or {}
    new_status = str(d.get("status", "")).upper().strip()
    if new_status not in VALID_INCIDENT_STATUSES:
        return jsonify(error=f"Invalid status '{new_status}'. Allowed: {list(VALID_INCIDENT_STATUSES)}"), 400
    rationale = str(d.get("rationale", "")).strip()[:1000]

    if new_status == "CLOSED" and not rationale:
        return jsonify(error="A closure rationale is required when closing an incident"), 400

    with db() as c:
        row = c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            return jsonify(error="Incident not found"), 404
        old_status = row["status"]
        closed_at = now() if new_status == "CLOSED" else (row["closed_at"] if new_status != "NEW" else None)
        closure_rationale = rationale if new_status == "CLOSED" else row["closure_rationale"]

        c.execute("""
            UPDATE incidents SET status = ?, updated_at = ?, closed_at = ?, closure_rationale = ?
            WHERE incident_id = ?
        """, (new_status, now(), closed_at, closure_rationale, incident_id))

        note_txt = f"Workflow status transitioned from {old_status} to {new_status}."
        if rationale:
            note_txt += f" Rationale: {rationale}"
        c.execute("""
            INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
            VALUES (?, 'SOC_ANALYST', ?, ?, 'STATUS_CHANGE')
        """, (incident_id, now(), note_txt))

        updated_row = c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        updated_inc = dict(updated_row)
        updated_inc["id"] = updated_inc["incident_id"]

    return jsonify(status="success", incident_id=incident_id, new_status=new_status, incident=updated_inc)

@app.post("/api/soc/incidents/<int:incident_id>/classify")
@auth("analyst")
def classify_incident(incident_id):
    d = request.get_json(silent=True) or {}
    classification = str(d.get("classification", "")).upper().strip()
    if classification not in VALID_CLASSIFICATIONS:
        return jsonify(error=f"Invalid classification '{classification}'. Allowed: {list(VALID_CLASSIFICATIONS)}"), 400
    rationale = str(d.get("rationale", "")).strip()[:1000]
    if not rationale:
        return jsonify(error="Classification rationale is required"), 400

    with db() as c:
        row = c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            return jsonify(error="Incident not found"), 404

        c.execute("""
            UPDATE incidents SET classification = ?, classification_rationale = ?, status = 'CLASSIFIED', updated_at = ?
            WHERE incident_id = ?
        """, (classification, rationale, now(), incident_id))

        note_txt = f"Incident classified as {classification}. Rationale: {rationale}"
        c.execute("""
            INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
            VALUES (?, 'SOC_ANALYST', ?, ?, 'CLASSIFICATION')
        """, (incident_id, now(), note_txt))

        updated_row = c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        updated_inc = dict(updated_row)
        updated_inc["id"] = updated_inc["incident_id"]

    return jsonify(status="success", incident_id=incident_id, classification=classification, incident=updated_inc)

@app.post("/api/soc/incidents/<int:incident_id>/notes")
@auth("analyst")
def add_incident_note(incident_id):
    d = request.get_json(silent=True) or {}
    text = str(d.get("note_text") or d.get("note") or "").strip()[:2000]
    if not text:
        return jsonify(error="Note text is required"), 400

    with db() as c:
        row = c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            return jsonify(error="Incident not found"), 404

        cur = c.execute("""
            INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
            VALUES (?, 'SOC_ANALYST', ?, ?, 'ANALYST_NOTE')
        """, (incident_id, now(), text))
        note_id = cur.lastrowid
        c.execute("UPDATE incidents SET updated_at = ? WHERE incident_id = ?", (now(), incident_id))

    return jsonify(status="success", note_id=note_id, incident_id=incident_id), 201

@app.get("/api/soc/alerts")
@auth("analyst")
def list_alerts():
    severity_filter = request.args.get("severity", "").lower().strip()
    source_filter = request.args.get("source_ip", "").strip()
    sig_filter = request.args.get("signature", "").upper().strip()
    limit = min(int(request.args.get("limit", 100)), 500)

    query = """
        SELECT a.id, a.event_id, a.source_ip, a.signature, a.severity, a.timestamp,
               a.message, a.mitre_id, a.incident_id, a.http_method, a.requested_path,
               a.response_status, a.detection_reason,
               i.title AS incident_title, i.status AS incident_status
        FROM alerts a
        LEFT JOIN incidents i ON a.incident_id = i.incident_id
        WHERE 1=1
    """
    params = []
    if severity_filter and severity_filter != "all":
        query += " AND a.severity = ?"
        params.append(severity_filter)
    if source_filter:
        query += " AND a.source_ip = ?"
        params.append(source_filter)
    if sig_filter and sig_filter != "ALL":
        query += " AND a.signature = ?"
        params.append(sig_filter)

    query += " ORDER BY a.id DESC LIMIT ?"
    params.append(limit)

    with db() as c:
        rows = c.execute(query, params).fetchall()
        alerts = []
        for r in rows:
            ad = dict(r)
            sig = ad["signature"]
            reg = REGISTRY.get(sig, (ad["mitre_id"] or "Unknown", sig, "Unknown"))
            ad["technique_id"] = reg[0]
            ad["technique_name"] = reg[1]
            ad["tactic"] = reg[2]
            alerts.append(ad)

    return jsonify(status="success", count=len(alerts), alerts=alerts)

@app.get("/api/soc/reports")
@auth("analyst")
def list_reports():
    with db() as c:
        rows = c.execute("""
            SELECT r.*, i.title as incident_title, i.severity as incident_severity, i.status as incident_status
            FROM reports r
            LEFT JOIN incidents i ON r.incident_id = i.incident_id
            ORDER BY r.report_id DESC
        """).fetchall()
        reports = [dict(r) for r in rows]
    return jsonify(status="success", count=len(reports), reports=reports)

@app.post("/api/soc/reports")
@auth("analyst")
def create_report():
    d = request.get_json(silent=True) or {}
    title = str(d.get("title", "")).strip()[:200]
    report_type = str(d.get("report_type", "")).strip()[:100]
    summary = str(d.get("summary", "")).strip()[:4000]
    findings = str(d.get("findings", "")).strip()[:4000]
    date_range = str(d.get("date_range", "")).strip()[:100]
    incident_id = d.get("incident_id")
    metadata_val = d.get("metadata", {})
    content_json = json.dumps(metadata_val) if isinstance(metadata_val, dict) else "{}"

    if not title:
        return jsonify(error="Report title is required"), 400
    if not report_type:
        return jsonify(error="Report type is required"), 400
    if not summary:
        return jsonify(error="Executive summary is required"), 400

    if incident_id is not None and str(incident_id).strip() != "":
        try:
            incident_id = int(incident_id)
        except (ValueError, TypeError):
            incident_id = None
    else:
        incident_id = None

    with db() as c:
        cur = c.execute("""
            INSERT INTO reports (incident_id, title, report_type, summary, findings, date_range, author, created_at, content_json)
            VALUES (?, ?, ?, ?, ?, ?, 'SOC_ANALYST', ?, ?)
        """, (incident_id, title, report_type, summary, findings, date_range, now(), content_json))
        report_id = cur.lastrowid

        if incident_id:
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SOC_ANALYST', ?, ?, 'ANALYST_NOTE')
            """, (incident_id, now(), f"Generated report #{report_id}: '{title}' ({report_type})."))

    return jsonify(status="success", report_id=report_id, message="Report generated and saved successfully"), 201

if __name__ == "__main__":
    init_db()
    conf = validate_startup_config()
    bind_host = conf["bind_host"]
    port = conf["port"]
    print(f"[*] Starting Mini Enterprise Defensive SOC Dashboard on http://{bind_host}:{port} (HTTP)")
    print(f"[*] Telemetry ingestion route: http://{bind_host}:{port}/api/events")
    print(f"[*] MITRE matrix route: http://{bind_host}:{port}/api/soc/mitre-matrix")
    print(f"[*] Active database: {conf['db_path']}")
    print(f"[*] Agent authentication: CONFIGURED ({conf['agent_token_len']} chars)")
    print(f"[*] Analyst authentication: CONFIGURED ({conf['analyst_token_len']} chars)")
    app.run(host=bind_host, port=port, debug=False)
