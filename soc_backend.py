"""Starter Flask SOC API with SQLite, response actions, MITRE aggregation, and Incident Investigation."""
import ipaddress, json, math, os, re, secrets, sqlite3, threading, time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List, Set
from flask import Flask, jsonify, request, render_template

try:
    from soc_ml_engine import ml_engine, MLInferenceResult
except ImportError:
    ml_engine = None
    MLInferenceResult = None

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
app.config["SOC_RATE_LIMIT_ENABLED"] = True
app.config["SOC_RATE_LIMIT_PER_MINUTE"] = 600

# ---------------------------------------------------------------------------
# Rate Limiting & Host IP Allowlist Security Controls
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """Thread-safe sliding-window rate limiter per client IP."""
    def __init__(self):
        self._lock = threading.Lock()
        self._requests: Dict[str, List[float]] = {}
        self._window = 60.0

    def is_allowed(self, client_ip: str, limit: int = 120) -> Tuple[bool, int, float]:
        if not app.config.get("SOC_RATE_LIMIT_ENABLED", True):
            return True, 0, 0.0
        now_ts = time.time()
        cutoff = now_ts - self._window
        with self._lock:
            history = self._requests.get(client_ip, [])
            valid = [t for t in history if t >= cutoff]
            if len(valid) >= limit:
                oldest = valid[0]
                retry_after = max(1.0, math.ceil((oldest + self._window) - now_ts))
                self._requests[client_ip] = valid
                return False, len(valid), retry_after
            valid.append(now_ts)
            self._requests[client_ip] = valid
            if len(self._requests) > 1000:
                self._requests = {ip: h for ip, h in self._requests.items() if h and h[-1] >= cutoff}
            return True, len(valid), 0.0

    def reset(self):
        with self._lock:
            self._requests.clear()

rate_limiter = TokenBucketRateLimiter()
unauth_rate_limiter = TokenBucketRateLimiter()

ALLOWED_AGENT_IPS = []
ALLOWED_ANALYST_IPS = []

def is_ip_allowed(client_ip: str, role: str) -> bool:
    """
    Check if client IP is permitted by role-specific allowlist.

    Allowlist Semantics:
    - An empty or unconfigured allowlist (the default) indicates unrestricted source IP access
      for that role. This behavior is intentionally retained for flexible deployments, but
      token authentication remains strictly required on all protected endpoints.
    - Explicit configuration:
      ALLOWED_AGENT_IPS: Comma-separated string or list of permitted agent IPs/CIDRs.
      ALLOWED_ANALYST_IPS: Comma-separated string or list of permitted analyst IPs/CIDRs.
    - Loopback access (127.0.0.1, ::1) is permitted only if SOC_ALLOW_LOOPBACK is enabled (default: true).
    """
    var_name = "ALLOWED_AGENT_IPS" if role == "agent" else "ALLOWED_ANALYST_IPS"
    allowlist_raw = app.config.get(var_name) or globals().get(var_name) or os.getenv(var_name, "")
    if not allowlist_raw:
        return True
    if isinstance(allowlist_raw, (list, tuple, set)):
        items = [str(x).strip() for x in allowlist_raw if str(x).strip()]
    else:
        items = [x.strip() for x in str(allowlist_raw).split(",") if x.strip()]
    if not items:
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    allow_loopback = str(app.config.get("SOC_ALLOW_LOOPBACK") or os.getenv("SOC_ALLOW_LOOPBACK", "true")).lower().strip() in ("true", "1", "yes")
    if ip.is_loopback:
        return allow_loopback

    for item in items:
        try:
            if "/" in item:
                if ip in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(item):
                    return True
        except ValueError:
            continue
    return False

@app.after_request
def apply_security_headers(response):
    """Enforce defensive HTTP security headers on all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'"
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response

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

def is_soar_dry_run() -> bool:
    """
    Check if SOAR operates in dry-run simulation mode (safe default: True).
    Real enforcement requires explicit, deliberate configuration:
    SOAR_ENFORCEMENT_MODE must be enabled AND SOAR_DRY_RUN must be explicitly disabled ('false', '0', 'disabled', 'no').
    If enforcement and dry-run settings conflict (both enabled), fail safely to DRY-RUN mode.
    """
    enforce_cfg = app.config.get("SOAR_ENFORCEMENT_MODE")
    if enforce_cfg is None:
        enforce_cfg = os.getenv("SOAR_ENFORCEMENT_MODE", "")
    enforce_val = str(enforce_cfg).lower().strip()
    enforce_enabled = enforce_val in ("true", "1", "enabled", "enforce", "enforcing", "yes")

    dry_cfg = app.config.get("SOAR_DRY_RUN")
    if dry_cfg is None:
        dry_cfg = os.getenv("SOAR_DRY_RUN", "")
    dry_val = str(dry_cfg).lower().strip()
    dry_disabled = dry_val in ("false", "0", "disabled", "no")

    if enforce_enabled and dry_disabled:
        return False

    if enforce_enabled and not dry_disabled:
        app.logger.warning(
            "SOAR configuration conflict: SOAR_ENFORCEMENT_MODE is enabled but SOAR_DRY_RUN is not explicitly disabled. "
            "Failing safely to DRY-RUN mode."
        )

    return True

def get_soar_mode() -> str:
    """Return 'DRY-RUN' or 'ENFORCEMENT'."""
    return "DRY-RUN" if is_soar_dry_run() else "ENFORCEMENT"

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
        "soar_dry_run": is_soar_dry_run(),
        "soar_mode": get_soar_mode(),
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

# ---------------------------------------------------------------------------
# Attack-Specific Response Policies
# ---------------------------------------------------------------------------
RESPONSE_POLICIES: Dict[str, Dict[str, Any]] = {
    "PORT_SCAN": {
        "signature": "PORT_SCAN",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Reconnaissance",
        "policy_name": "Port Scan Rate-Limiting & Temporary Restriction Policy",
        "trigger_conditions": "Confirmed network port scan telemetry with multiple probed destination ports",
        "selected_response": "RATE_LIMIT_OR_TEMPORARY_RESTRICTION",
        "action_type": "BLOCK_IP",
        "scope": "network_layer",
        "duration_seconds": 1800,
        "verification_method": "host_nftables_query",
        "is_supported": True,
        "description": "Rate-limit or temporarily restrict confirmed scanner source IP in host firewall table inet mini_enterprise set blocked_ips.",
        "pending_reason": None,
    },
    "DIR_FUZZ": {
        "signature": "DIR_FUZZ",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "policy_name": "Directory Discovery Enumeration Throttling & Restriction Policy",
        "trigger_conditions": "Repeated distinct 404 path probes exceeding threshold within window, or explicit sensitive backup/environment target probing",
        "selected_response": "ENUMERATION_THROTTLING_AND_TEMPORARY_RESTRICTION",
        "action_type": "BLOCK_IP",
        "scope": "application_and_network_layer",
        "duration_seconds": 900,
        "verification_method": "host_nftables_query",
        "is_supported": True,
        "description": "Apply enumeration throttling via probe tracker; apply temporary firewall restriction for sustained abusive probing.",
        "pending_reason": None,
    },
    "PATH_TRAVERSAL": {
        "signature": "PATH_TRAVERSAL",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "policy_name": "Path Traversal Request Rejection & File Audit Policy",
        "trigger_conditions": "Directory traversal probe sequence (e.g. '../', '%2e%2e%2f') detected in request path",
        "selected_response": "REJECT_REQUEST_AND_INVESTIGATE",
        "action_type": "APP_REJECT",
        "scope": "application_layer",
        "duration_seconds": None,
        "verification_method": "http_status_rejection_audit",
        "is_supported": False,
        "description": "Reject malicious requests (HTTP 400/403) at web application tier and investigate attempted file access. Firewall IP block is not primary mitigation.",
        "pending_reason": "Application-layer path sanitizer / web tier reverse proxy filter pending deployment. Firewall block is not the primary mitigation.",
    },
    "SQL_INJECTION": {
        "signature": "SQL_INJECTION",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "policy_name": "SQL Injection Application-Layer Protection Policy",
        "trigger_conditions": "SQL injection syntax, boolean tautologies, or union probes detected in query parameters or payload",
        "selected_response": "APPLICATION_LAYER_PROTECTION",
        "action_type": "APP_REJECT",
        "scope": "application_database_layer",
        "duration_seconds": None,
        "verification_method": "waf_query_audit",
        "is_supported": False,
        "description": "Reject malicious requests and use application-layer protection (parameterized queries, input validation); firewall block does not prevent SQL injection.",
        "pending_reason": "Application-layer parameterized query enforcement and WAF inspection pending deployment. Host firewall block does not mitigate SQL injection.",
    },
    "BRUTE_FORCE_AUTH": {
        "signature": "BRUTE_FORCE_AUTH",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "policy_name": "Authentication Throttling & Progressive Delay Policy",
        "trigger_conditions": "Consecutive failed login attempts exceeding threshold from source IP or against targeted account",
        "selected_response": "AUTH_THROTTLING_AND_ACCOUNT_LOCKOUT",
        "action_type": "AUTH_THROTTLE",
        "scope": "identity_authentication_layer",
        "duration_seconds": 600,
        "verification_method": "auth_audit_log",
        "is_supported": False,
        "description": "Apply authentication throttling, progressive delays (exponential backoff), and appropriate account-aware controls. Avoid automatic permanent blocking.",
        "pending_reason": "Authentication service progressive backoff, CAPTCHA challenge, and account-aware lockout instrumentation pending deployment.",
    },
    "COMMAND_INJECTION": {
        "signature": "COMMAND_INJECTION",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "policy_name": "Command Injection Request Rejection & Process Audit Policy",
        "trigger_conditions": "Shell metacharacters, pipe operators, or command execution sequences detected in input parameters",
        "selected_response": "REJECT_REQUEST_AND_AUDIT_EXECUTION",
        "action_type": "APP_REJECT",
        "scope": "application_and_os_layer",
        "duration_seconds": None,
        "verification_method": "process_audit_inspection",
        "is_supported": False,
        "description": "Reject the request at application layer and investigate possible command execution across host process tree.",
        "pending_reason": "Host process execution auditing and application input sanitizer pending deployment. Firewall blocking is insufficient.",
    },
}

SAFE_FALLBACK_POLICY: Dict[str, Any] = {
    "signature": "UNKNOWN",
    "technique_id": "T1000",
    "technique_name": "Unclassified Technique",
    "tactic": "Triage",
    "policy_name": "Safe Fallback Triage Policy",
    "trigger_conditions": "Unrecognized or unmapped security event signature",
    "selected_response": "ALERT_AND_MANUAL_TRIAGE",
    "action_type": "LOG_MONITOR",
    "scope": "soc_triage",
    "duration_seconds": None,
    "verification_method": "manual_analyst_review",
    "is_supported": True,
    "description": "Safe fallback for unknown signatures: record alert, notify analyst for manual review, and do not execute automatic permanent or host-level containment.",
    "pending_reason": None,
}

def get_response_policy(signature: Optional[str]) -> Dict[str, Any]:
    """
    Return explicit response policy for an alert signature.
    Normalizes signature and falls back safely for unknown signatures.
    """
    if not signature or not isinstance(signature, str):
        fallback = dict(SAFE_FALLBACK_POLICY)
        fallback["signature"] = "UNKNOWN"
        return fallback

    cleaned = signature.upper().strip()
    canonical_sig = EVENT_NORMALIZATION.get(cleaned, cleaned)

    if canonical_sig in RESPONSE_POLICIES:
        return dict(RESPONSE_POLICIES[canonical_sig])

    fallback = dict(SAFE_FALLBACK_POLICY)
    fallback["signature"] = canonical_sig
    fallback["description"] = f"Safe fallback for unknown signature '{signature}': alert recorded for analyst review; automatic containment avoided."
    return fallback

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

# Canonical 6 Defense Lifecycle States:
# Detected, Mitigation Applied, Verification Pending, Verified, Verification Failed, Expired
DEFENSE_STATES = (
    "Detected",
    "Mitigation Applied",
    "Verification Pending",
    "Verified",
    "Verification Failed",
    "Expired"
)

DEFENSE_STATE_NORMALIZATION = {
    "DETECTED": "Detected",
    "NEW": "Detected",
    "TRIAGE": "Detected",
    "INVESTIGATING": "Detected",
    "CLASSIFIED": "Detected",
    "RESPONSE_REQUESTED": "Detected",
    "CONTAINMENT_PENDING_APPROVAL": "Verification Pending",
    "MITIGATION_APPLIED": "Mitigation Applied",
    "EXECUTED": "Mitigation Applied",
    "VERIFICATION_PENDING": "Verification Pending",
    "VERIFIED": "Verified",
    "CONTAINED": "Verified",
    "VERIFICATION_FAILED": "Verification Failed",
    "EXPIRED": "Expired",
    "CLOSED": "Detected",  # Closing an incident alone does NOT make it verified
}

# Formal Investigation Classification Categories
VALID_CLASSIFICATIONS = (
    "CONFIRMED_MALICIOUS",
    "BENIGN_AUTHORIZED_TESTING",
    "INCONCLUSIVE"
)

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def parse_iso_ts(ts_str: str) -> float:
    """Parse ISO8601 or standard UTC timestamp string into unix epoch seconds."""
    if not ts_str:
        return time.time()
    try:
        clean = ts_str.strip()
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        return datetime.fromisoformat(clean).timestamp()
    except Exception:
        pass
    try:
        return time.mktime(time.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return time.time()

def compute_action_expiry(action: Dict[str, Any], current_time: Optional[float] = None) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Evaluate if a temporary containment action has passed its timeout duration.
    Returns: (is_expired: bool, time_remaining_seconds: Optional[int], expires_at_iso: Optional[str])
    """
    timeout = action.get("timeout_seconds")
    if timeout is None:
        return False, None, None
    try:
        timeout = int(timeout)
    except (ValueError, TypeError):
        return False, None, None

    if timeout <= 0:
        return False, None, None

    status = action.get("status", "")
    executed_at = action.get("executed_at")

    # Actions pending approval have not yet executed; their timer has not started
    if status in ("PENDING", "APPROVED"):
        return False, timeout, None

    # For actions in VERIFICATION_PENDING, preserve status until valid verification evidence is supplied
    if status == "VERIFICATION_PENDING":
        if not executed_at:
            return False, timeout, None
        base_epoch = parse_iso_ts(executed_at)
        expires_epoch = base_epoch + timeout
        now_epoch = current_time if current_time is not None else time.time()
        remaining = max(0, int(expires_epoch - now_epoch))
        expires_iso = datetime.fromtimestamp(expires_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return False, remaining, expires_iso

    base_ts = executed_at or action.get("created_at") or now()
    base_epoch = parse_iso_ts(base_ts)
    expires_epoch = base_epoch + timeout

    now_epoch = current_time if current_time is not None else time.time()
    remaining = max(0, int(expires_epoch - now_epoch))
    is_expired = now_epoch >= expires_epoch

    # Format with standard Z for unambiguous JavaScript Date parsing:
    expires_iso = datetime.fromtimestamp(expires_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return is_expired, remaining, expires_iso

def check_and_update_expired_controls(c: sqlite3.Connection, current_time: Optional[float] = None):
    """
    Evaluate active temporary containment controls and transition expired ones to EXPIRED.
    Ensures active verified mitigations reflect real-time host status.
    """
    rows = c.execute("""
        SELECT action_id, incident_id, target_ip, action_type, status, created_at, executed_at, timeout_seconds
        FROM response_actions
        WHERE timeout_seconds IS NOT NULL AND timeout_seconds > 0
          AND status IN ('VERIFIED', 'EXECUTED', 'MITIGATION_APPLIED')
    """).fetchall()

    for r in rows:
        act_dict = dict(r)
        is_expired, remaining, expires_iso = compute_action_expiry(act_dict, current_time)
        if is_expired:
            aid = act_dict["action_id"]
            c.execute("""
                UPDATE response_actions
                SET status = 'EXPIRED', expires_at = ?, message = COALESCE(message, '') || ' [EXPIRED: timeout reached]'
                WHERE action_id = ?
            """, (expires_iso, aid))
            inc_id = act_dict.get("incident_id")
            if inc_id:
                other_active = c.execute("""
                    SELECT action_id FROM response_actions
                    WHERE incident_id = ? AND action_id != ? AND status = 'VERIFIED'
                """, (inc_id, aid)).fetchone()
                if not other_active:
                    c.execute("""
                        UPDATE incidents SET defense_status = 'Expired', updated_at = ? WHERE incident_id = ?
                    """, (now(), inc_id))
                    c.execute("""
                        INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                        VALUES (?, 'SYSTEM', ?, ?, 'STATUS_CHANGE')
                    """, (inc_id, now(), f"Temporary containment action #{aid} for target {act_dict['target_ip']} expired ({act_dict['timeout_seconds']}s timeout elapsed). Status: EXPIRED."))

def validate_verification_evidence(action: Dict[str, Any], evidence_data: Optional[Any] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate verification evidence for a containment response action.
    Returns: (is_valid: bool, reason_or_summary: str, structured_evidence: dict)

    Strict Verification Invariants:
    - Never generate, assume, or fabricate firewall evidence.
    - Missing, malformed, stale, or insufficient evidence must fail verification.
    - An action must not become VERIFIED merely because its status says EXECUTED or MITIGATION_APPLIED.
    - Separate action execution status from independently verified mitigation status.
    - Require evidence that is tied to the correct action ID, target IP, action type, and verification time.
    - Reject mismatched targets or unrelated firewall output.
    - A string containing 'table inet', 'set blocked_ips', 'drop', or 'reject' is not sufficient proof on its own.
      Verification must establish that the intended set exists in the live nftables ruleset and that an active
      rule actually references that set (e.g. 'ip saddr @blocked_ips counter drop').
    - For UNBLOCK_IP: Confirm target IP is absent from block set and no other active rule still blocks it.
    """
    target_ip = str(action.get("target_ip", "")).strip()
    current_status = str(action.get("status", "")).strip()
    action_id = action.get("action_id")
    action_type = str(action.get("action_type") or "BLOCK_IP").upper().strip()

    if current_status in ("PENDING", "FAILED", "CANCELLED"):
        return False, f"Cannot verify action #{action_id} in '{current_status}' state (must be approved and executed)", {}

    evidence_dict: Dict[str, Any] = {}
    evidence_str = ""

    # 1. Parse incoming evidence or retrieve stored evidence without synthetic fallbacks
    raw_ev = evidence_data
    if (raw_ev is None or raw_ev == {} or raw_ev == "") and action.get("verification_evidence"):
        stored = action.get("verification_evidence")
        if isinstance(stored, str):
            try:
                raw_ev = json.loads(stored)
            except Exception:
                raw_ev = stored
        else:
            raw_ev = stored

    if raw_ev is None or raw_ev == {} or raw_ev == "":
        return False, "Verification failed: missing verification evidence. Authentic host firewall proof is required.", {}

    if isinstance(raw_ev, dict):
        evidence_dict = dict(raw_ev)
        if evidence_dict.get("verified") is False or evidence_dict.get("success") is False:
            reason = evidence_dict.get("reason") or evidence_dict.get("error") or "Verifier reported explicit verification failure"
            return False, f"Verification failed: {reason}", evidence_dict

        evidence_str = str(
            evidence_dict.get("output")
            or evidence_dict.get("evidence")
            or evidence_dict.get("rule")
            or evidence_dict.get("detail")
            or evidence_dict.get("details")
            or ""
        ).strip()
    elif isinstance(raw_ev, str):
        trimmed = raw_ev.strip()
        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                parsed = json.loads(trimmed)
                if isinstance(parsed, dict):
                    evidence_dict = dict(parsed)
                    if evidence_dict.get("verified") is False or evidence_dict.get("success") is False:
                        reason = evidence_dict.get("reason") or evidence_dict.get("error") or "Verifier reported explicit verification failure"
                        return False, f"Verification failed: {reason}", evidence_dict
                    evidence_str = str(
                        evidence_dict.get("output")
                        or evidence_dict.get("evidence")
                        or evidence_dict.get("rule")
                        or evidence_dict.get("detail")
                        or evidence_dict.get("details")
                        or ""
                    ).strip()
                else:
                    evidence_str = trimmed
                    evidence_dict = {"raw_evidence": evidence_str}
            except Exception:
                evidence_str = trimmed
                evidence_dict = {"raw_evidence": evidence_str}
        else:
            evidence_str = trimmed
            evidence_dict = {"raw_evidence": evidence_str}
    else:
        return False, "Verification failed: invalid evidence format (must be dict or string).", {}

    if not evidence_str and not evidence_dict:
        return False, "Verification failed: empty verification evidence.", evidence_dict

    # 2. Reject DRY_RUN or simulated/dry-run evidence notes without authentic kernel nftables proof
    action_msg = str(action.get("message") or "").strip().lower()
    is_dry_run_action = (
        current_status == "DRY_RUN"
        or action.get("triggered_by") in ("DRY_RUN", "SIMULATION")
        or action_msg.startswith(("[dry_run]", "dry_run:", "dry-run:", "[dry run]"))
    )
    if is_dry_run_action:
        return False, "Verification rejected: action was executed in DRY_RUN simulation mode. Simulated actions cannot be verified as active host-firewall containment without authentic kernel enforcement.", evidence_dict

    combined_text = (evidence_str + " " + str(evidence_dict)).lower()
    if any(k in combined_text for k in ("dry_run", "dry-run", "dry run", "simulat", "without nftables", "no actual firewall", "mock_verification", "fake_evidence")):
        return False, "Verification failed: evidence indicates DRY_RUN simulation mode; no actual firewall rule was added to host nftables.", evidence_dict

    failure_indicators = [
        "not found", "no such element", "table not found", "set not found",
        "error:", "does not exist", "absent", "connection refused",
        "could not inspect", "without nftables", "no actual firewall"
    ]
    for ind in failure_indicators:
        if ind in combined_text and not any(pos in combined_text for pos in ("verified successfully", "element found", "confirmed", "absent from set")):
            return False, f"Verification failed: evidence contains error/absence indicator ('{ind}'): {evidence_str[:200]}", evidence_dict

    # 3. Action ID correlation
    ev_aid = evidence_dict.get("action_id") or evidence_dict.get("id")
    if ev_aid is not None and str(ev_aid).strip() != str(action_id).strip():
        return False, f"Verification failed: evidence action ID '{ev_aid}' does not match action #{action_id}", evidence_dict

    # 4. Action Type correlation
    ev_kind = evidence_dict.get("action_type") or evidence_dict.get("type")
    if ev_kind and str(ev_kind).upper().strip() != action_type:
        return False, f"Verification failed: evidence action type '{ev_kind}' does not match action type '{action_type}'", evidence_dict

    # 5. Target IP validation and correlation
    try:
        valid_ip(target_ip)
    except Exception as e:
        return False, f"Verification failed: action target IP '{target_ip}' is invalid: {str(e)}", evidence_dict

    ev_ip = evidence_dict.get("target_ip") or evidence_dict.get("ip")
    if ev_ip and str(ev_ip).strip() != target_ip:
        return False, f"Verification failed: evidence target IP '{ev_ip}' does not match action target IP '{target_ip}'", evidence_dict

    # 6. Timestamp verification
    ev_ts = evidence_dict.get("timestamp") or evidence_dict.get("verified_at")
    if ev_ts:
        try:
            ts_val = parse_iso_ts(ev_ts) if isinstance(ev_ts, str) else float(ev_ts)
            now_ts = time.time()
            if ts_val > (now_ts + 300):
                return False, f"Verification failed: evidence timestamp is in the future ({ev_ts})", evidence_dict
            if (now_ts - ts_val) > 86400 * 7:
                return False, f"Verification failed: evidence timestamp is stale ({ev_ts})", evidence_dict
        except Exception:
            pass

    import re
    lower_ev = evidence_str.lower()
    found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", evidence_str)

    # 7. Action Type Specific Verification
    if action_type == "BLOCK_IP":
        elements_list = [str(x) for x in evidence_dict.get("elements", [])]
        if target_ip not in found_ips and target_ip not in elements_list:
            return False, f"Verification failed: evidence IP(s) {found_ips} do not contain expected target IP '{target_ip}' (target IP does not match)", evidence_dict

        # Confirm intended nftables table and set exist
        firewall_syntax_keywords = (
            "table inet", "table ip", "set blocked_ips", "chain input", "chain forward",
            "type ipv4_addr", "elements =", "ip saddr", "ip daddr"
        )
        has_syntax = any(kw in lower_ev for kw in firewall_syntax_keywords) or (
            evidence_dict.get("table") and evidence_dict.get("set")
        )
        if not has_syntax:
            return False, "Verification failed: evidence is arbitrary text without valid firewall/nftables syntax.", evidence_dict

        # Reject non-blocking rules (e.g. accept without drop/reject)
        if "accept" in lower_ev and "drop" not in lower_ev and "reject" not in lower_ev and not evidence_dict.get("rule_references_set"):
            return False, "Verification failed: evidence does not demonstrate an active drop/reject rule; no active drop/reject rule references set @blocked_ips (accept rule found).", evidence_dict

        # Confirm an active firewall rule references the set and applies intended drop/reject behavior
        rule_str = str(evidence_dict.get("rule") or "").lower()
        has_set_ref = (
            evidence_dict.get("rule_references_set") is True
            or bool(re.search(r"@(?:blocked_ips|[a-zA-Z0-9_\-]+)\s+(?:counter\s+)?(?:drop|reject)", lower_ev))
            or bool(re.search(r"ip\s+saddr\s+@(?:blocked_ips|[a-zA-Z0-9_\-]+).*?(?:drop|reject)", lower_ev))
            or bool(re.search(r"@(?:blocked_ips|[a-zA-Z0-9_\-]+)\s+(?:counter\s+)?(?:drop|reject)", rule_str))
            or bool(re.search(r"ip\s+saddr\s+@(?:blocked_ips|[a-zA-Z0-9_\-]+).*?(?:drop|reject)", rule_str))
        )

        if not has_set_ref:
            return False, "Verification failed: block set exists but no active drop/reject rule references set @blocked_ips.", evidence_dict

        # Check block expiration/timeout when applicable
        if action.get("timeout_seconds"):
            is_exp, rem, _ = compute_action_expiry(action)
            if is_exp:
                return False, "Verification failed: temporary block action has expired.", evidence_dict

        summary = evidence_str[:500] if evidence_str else f"Firewall containment verified for target {target_ip} in table {evidence_dict.get('table', 'mini_enterprise')} set {evidence_dict.get('set', 'blocked_ips')}"

    elif action_type == "UNBLOCK_IP":
        elements_list = [str(x) for x in evidence_dict.get("elements", [])]
        if target_ip in elements_list:
            return False, f"Verification failed: target IP '{target_ip}' is still present in block set elements.", evidence_dict

        if "set blocked_ips" in lower_ev and "elements" in lower_ev and target_ip in found_ips:
            return False, f"Verification failed: target IP '{target_ip}' is still present in block set elements.", evidence_dict

        if evidence_dict.get("other_blocking_rules") is True:
            return False, f"Verification failed: another active firewall rule still blocks target IP '{target_ip}'.", evidence_dict

        if re.search(rf"ip\s+saddr\s+{re.escape(target_ip)}.*?(?:drop|reject)", lower_ev):
            return False, f"Verification failed: target IP '{target_ip}' is still blocked by an active firewall rule.", evidence_dict

        summary = evidence_str[:500] if evidence_str else f"Rollback unblock verified for target {target_ip}: absent from block set and no active blocking rules"

    else:
        return False, f"Verification failed: action type '{action_type}' requires application-level instrumentation pending deployment.", evidence_dict

    evidence_dict.setdefault("verified", True)
    evidence_dict.setdefault("target_ip", target_ip)
    evidence_dict.setdefault("action_id", action_id)
    evidence_dict.setdefault("action_type", action_type)
    evidence_dict.setdefault("verifier", evidence_dict.get("verifier", "host_nftables_query"))
    evidence_dict.setdefault("summary", summary)
    evidence_dict.setdefault("timestamp", now())

    return True, summary, evidence_dict

def resolve_incident_defense_status(inc: Dict[str, Any], actions: List[Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Determine the canonical defense status for an incident from its response actions.
    States: Detected, Mitigation Applied, Verification Pending, Verified, Verification Failed, Expired.
    Rule: A closed incident is NOT marked verified merely because it is closed.
    """
    if not actions:
        explicit_st = inc.get("status")
        if explicit_st in ("DETECTED", "MITIGATION_APPLIED", "VERIFICATION_PENDING", "VERIFIED", "VERIFICATION_FAILED", "EXPIRED"):
            return DEFENSE_STATE_NORMALIZATION.get(explicit_st, "Detected"), None
        return "Detected", None

    sorted_actions = sorted(actions, key=lambda a: int(a["action_id"]), reverse=True)

    # 1. Any unexpired VERIFIED action -> Verified
    verified_acts = [a for a in sorted_actions if a.get("status") == "VERIFIED" and not a.get("is_expired")]
    if verified_acts:
        return "Verified", verified_acts[0]

    # 2. Latest action state
    latest = sorted_actions[0]
    st = latest.get("status")
    if latest.get("is_expired") or st == "EXPIRED":
        return "Expired", latest
    if st == "VERIFICATION_FAILED":
        return "Verification Failed", latest
    if st == "VERIFICATION_PENDING":
        return "Verification Pending", latest
    if st in ("EXECUTED", "MITIGATION_APPLIED"):
        return "Mitigation Applied", latest
    if st == "APPROVED":
        return "Verification Pending", latest

    inc_st = inc.get("status")
    if inc_st in DEFENSE_STATE_NORMALIZATION:
        if inc_st == "CLOSED":
            return "Detected", None
        return DEFENSE_STATE_NORMALIZATION[inc_st], None

    return "Detected", None

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
          http_method TEXT, requested_path TEXT, response_status INTEGER, detection_reason TEXT,
          metadata_json TEXT, destination_ip TEXT, destination_port INTEGER, protocol TEXT);
        CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON alerts(mitre_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip);

        CREATE TABLE IF NOT EXISTS response_actions(
          action_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER,
          target_ip TEXT NOT NULL, action_type TEXT NOT NULL CHECK(action_type IN ('BLOCK_IP','UNBLOCK_IP','RATE_LIMIT','APP_REJECT','AUTH_THROTTLE','LOG_MONITOR')),
          status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','EXECUTED','MITIGATION_APPLIED','VERIFICATION_PENDING','VERIFIED','VERIFICATION_FAILED','EXPIRED','FAILED','CANCELLED','DRY_RUN','UNSUPPORTED','PENDING_IMPLEMENTATION')),
          triggered_by TEXT NOT NULL CHECK(triggered_by IN ('AUTO_RULE','SOC_ANALYST')),
          created_at TEXT NOT NULL, executed_at TEXT, timeout_seconds INTEGER,
          message TEXT NOT NULL DEFAULT '',
          verification_evidence TEXT, verified_at TEXT, expires_at TEXT);
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
          closure_rationale TEXT NOT NULL DEFAULT '',
          defense_status TEXT NOT NULL DEFAULT 'Detected',
          verification_evidence TEXT
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

        # Safe migration: ensure columns exist on alerts
        cols_alerts = [r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()]
        if "incident_id" not in cols_alerts:
            c.execute("ALTER TABLE alerts ADD COLUMN incident_id INTEGER REFERENCES incidents(incident_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")

        for col_name, col_type in [
            ("http_method", "TEXT"),
            ("requested_path", "TEXT"),
            ("response_status", "INTEGER"),
            ("detection_reason", "TEXT"),
            ("metadata_json", "TEXT"),
            ("destination_ip", "TEXT"),
            ("destination_port", "INTEGER"),
            ("protocol", "TEXT"),
            ("classification_type", "TEXT DEFAULT 'known_attack'"),
            ("detection_method", "TEXT DEFAULT 'rule'"),
            ("confidence", "REAL"),
            ("anomaly_score", "REAL"),
            ("model_name", "TEXT"),
            ("model_version", "TEXT"),
            ("status", "TEXT DEFAULT 'new'"),
            ("analyst_disposition", "TEXT"),
            ("measurement_window_seconds", "INTEGER"),
            ("threshold_value", "REAL"),
            ("observed_value", "REAL"),
        ]:
            if col_name not in cols_alerts:
                c.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")

        # Indices for alert filtering
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_class ON alerts(classification_type)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")

        # Create alert_notes, soc_security_events, and ingestion_telemetry tables
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alert_notes(
          note_id INTEGER PRIMARY KEY AUTOINCREMENT,
          alert_id INTEGER NOT NULL REFERENCES alerts(id),
          author TEXT NOT NULL DEFAULT 'SOC_ANALYST',
          created_at TEXT NOT NULL,
          note_text TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes(alert_id);

        CREATE TABLE IF NOT EXISTS soc_security_events(
          event_id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp TEXT NOT NULL,
          event_type TEXT NOT NULL,
          source_ip TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'medium',
          details TEXT NOT NULL DEFAULT '',
          occurrence_count INTEGER NOT NULL DEFAULT 1,
          last_seen TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sec_events_type ON soc_security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_sec_events_src ON soc_security_events(source_ip);

        CREATE TABLE IF NOT EXISTS ingestion_telemetry(
          metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp TEXT NOT NULL,
          source_ip TEXT NOT NULL,
          event_id TEXT,
          status TEXT NOT NULL,
          error_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ingest_time ON ingestion_telemetry(timestamp);
        """)

        # Safe migration: ensure columns exist on response_actions
        cols_actions = [r[1] for r in c.execute("PRAGMA table_info(response_actions)").fetchall()]
        for col_name, col_type in [
            ("verification_evidence", "TEXT"),
            ("verified_at", "TEXT"),
            ("expires_at", "TEXT"),
        ]:
            if col_name not in cols_actions:
                c.execute(f"ALTER TABLE response_actions ADD COLUMN {col_name} {col_type}")

        # Test if response_actions supports new status and action_type values
        try:
            c.execute("INSERT INTO response_actions (target_ip, action_type, status, triggered_by, created_at) VALUES ('127.0.0.1', 'BLOCK_IP', 'PENDING_IMPLEMENTATION', 'AUTO_RULE', '1970-01-01T00:00:00Z')")
            c.execute("DELETE FROM response_actions WHERE target_ip='127.0.0.1' AND created_at='1970-01-01T00:00:00Z'")
        except sqlite3.IntegrityError:
            c.execute("ALTER TABLE response_actions RENAME TO _response_actions_old")
            c.execute("""
            CREATE TABLE response_actions(
              action_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER,
              target_ip TEXT NOT NULL, action_type TEXT NOT NULL CHECK(action_type IN ('BLOCK_IP','UNBLOCK_IP','RATE_LIMIT','APP_REJECT','AUTH_THROTTLE','LOG_MONITOR')),
              status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','EXECUTED','MITIGATION_APPLIED','VERIFICATION_PENDING','VERIFIED','VERIFICATION_FAILED','EXPIRED','FAILED','CANCELLED','DRY_RUN','UNSUPPORTED','PENDING_IMPLEMENTATION')),
              triggered_by TEXT NOT NULL CHECK(triggered_by IN ('AUTO_RULE','SOC_ANALYST')),
              created_at TEXT NOT NULL, executed_at TEXT, timeout_seconds INTEGER,
              message TEXT NOT NULL DEFAULT '',
              verification_evidence TEXT, verified_at TEXT, expires_at TEXT);
            """)
            cols_old_actions = [r[1] for r in c.execute("PRAGMA table_info(_response_actions_old)").fetchall()]
            has_extra = ("verification_evidence" in cols_old_actions and "verified_at" in cols_old_actions and "expires_at" in cols_old_actions)
            if has_extra:
                c.execute("""
                INSERT INTO response_actions (action_id, incident_id, target_ip, action_type, status, triggered_by, created_at, executed_at, timeout_seconds, message, verification_evidence, verified_at, expires_at)
                SELECT action_id, incident_id, target_ip, action_type, status, triggered_by, created_at, executed_at, timeout_seconds, message, verification_evidence, verified_at, expires_at
                FROM _response_actions_old;
                """)
            else:
                c.execute("""
                INSERT INTO response_actions (action_id, incident_id, target_ip, action_type, status, triggered_by, created_at, executed_at, timeout_seconds, message)
                SELECT action_id, incident_id, target_ip, action_type, status, triggered_by, created_at, executed_at, timeout_seconds, message
                FROM _response_actions_old;
                """)
            c.execute("DROP TABLE _response_actions_old")
            c.execute("CREATE INDEX IF NOT EXISTS idx_actions_status ON response_actions(status, action_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions(incident_id)")

        # Safe migration: ensure columns exist on incidents
        cols_incidents = [r[1] for r in c.execute("PRAGMA table_info(incidents)").fetchall()]
        if "defense_status" not in cols_incidents:
            c.execute("ALTER TABLE incidents ADD COLUMN defense_status TEXT NOT NULL DEFAULT 'Detected'")
        if "verification_evidence" not in cols_incidents:
            c.execute("ALTER TABLE incidents ADD COLUMN verification_evidence TEXT")

        # Normalize any missing or legacy defense status values
        c.execute("UPDATE incidents SET defense_status = 'Detected' WHERE defense_status IS NULL OR defense_status = ''")
        c.execute("UPDATE incidents SET defense_status = 'Detected', status = 'NEW' WHERE status = 'DETECTED'")
        c.execute("UPDATE incidents SET defense_status = 'Mitigation Applied', status = 'CONTAINED' WHERE status = 'MITIGATION_APPLIED'")
        c.execute("UPDATE incidents SET defense_status = 'Verification Pending', status = 'CONTAINMENT_PENDING_APPROVAL' WHERE status = 'VERIFICATION_PENDING'")
        c.execute("UPDATE incidents SET defense_status = 'Verified', status = 'CONTAINED' WHERE status = 'VERIFIED'")
        c.execute("UPDATE incidents SET defense_status = 'Verification Failed', status = 'INVESTIGATING' WHERE status = 'VERIFICATION_FAILED'")
        c.execute("UPDATE incidents SET defense_status = 'Expired', status = 'CLOSED' WHERE status = 'EXPIRED'")

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
                    INSERT INTO incidents (title, status, severity, source_ip, signature, mitre_id, created_at, updated_at, defense_status)
                    VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?, 'Detected')
                """, (title, max_sev, sip, sig, mitre, earliest_ts, latest_ts))
                inc_id = cur_inc.lastrowid

                alert_ids = [a["id"] for a in alert_list]
                c.execute(f"UPDATE alerts SET incident_id = ? WHERE id IN ({','.join('?' for _ in alert_ids)})", [inc_id] + alert_ids)

                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SYSTEM', ?, ?, 'SYSTEM')
                """, (inc_id, now(), f"Incident initialized with {len(alert_list)} existing alert(s)."))

        fk_violations = c.execute("PRAGMA foreign_key_check").fetchall()
        if fk_violations:
            raise sqlite3.IntegrityError(f"Foreign key violations detected during database initialization: {fk_violations}")

def log_soc_security_event(
    event_type: str,
    source_ip: str,
    endpoint: str,
    severity: str = "medium",
    details: str = "",
    c: Optional[sqlite3.Connection] = None
):
    """
    Record internal SOC security event with deduplication to prevent alert storms.
    """
    valid_types = (
        "FAILED_LOGIN", "INVALID_TOKEN", "UNAUTHORIZED_ACCESS",
        "RATE_LIMIT_EXCEEDED", "MALFORMED_PAYLOAD", "SUSPICIOUS_ACCESS",
        "UNAUTHORIZED_CONTAINMENT", "SERVICE_FAILURE", "IP_RESTRICTED"
    )
    if event_type not in valid_types:
        event_type = "UNAUTHORIZED_ACCESS"
    current_ts = now()
    clean_ip = str(source_ip or "unknown")[:64]
    clean_endpoint = str(endpoint or "")[:128]
    clean_details = str(details or "")[:1000]

    def _do_log(conn):
        recent = conn.execute("""
            SELECT event_id, occurrence_count, last_seen
            FROM soc_security_events
            WHERE event_type = ? AND source_ip = ? AND endpoint = ?
            ORDER BY event_id DESC LIMIT 1
        """, (event_type, clean_ip, clean_endpoint)).fetchone()

        if recent:
            try:
                last_ts = parse_iso_ts(recent["last_seen"])
                now_ts = parse_iso_ts(current_ts)
                if (now_ts - last_ts) < 60.0:
                    conn.execute("""
                        UPDATE soc_security_events
                        SET occurrence_count = occurrence_count + 1, last_seen = ?, details = ?
                        WHERE event_id = ?
                    """, (current_ts, clean_details, recent["event_id"]))
                    return
            except Exception:
                pass

        conn.execute("""
            INSERT INTO soc_security_events
            (timestamp, event_type, source_ip, endpoint, severity, details, occurrence_count, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """, (current_ts, event_type, clean_ip, clean_endpoint, severity, clean_details, current_ts))

    try:
        if c is not None:
            _do_log(c)
        else:
            with db() as conn:
                _do_log(conn)
    except Exception as exc:
        app.logger.warning(f"Failed to record SOC security event: {exc}")

def record_ingestion_metric(source_ip: str, status: str, event_id: Optional[str] = None, error: Optional[str] = None, c: Optional[sqlite3.Connection] = None):
    """Safely log telemetry delivery and processing metrics."""
    try:
        if c is not None:
            c.execute("""
                INSERT INTO ingestion_telemetry (timestamp, source_ip, event_id, status, error_reason)
                VALUES (?, ?, ?, ?, ?)
            """, (now(), str(source_ip or "unknown")[:64], str(event_id or "")[:64] if event_id else None, status, str(error or "")[:500] if error else None))
        else:
            with db() as conn:
                conn.execute("""
                    INSERT INTO ingestion_telemetry (timestamp, source_ip, event_id, status, error_reason)
                    VALUES (?, ?, ?, ?, ?)
                """, (now(), str(source_ip or "unknown")[:64], str(event_id or "")[:64] if event_id else None, status, str(error or "")[:500] if error else None))
    except Exception:
        pass

def auth(role):
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            client_ip = request.remote_addr or "127.0.0.1"

            # 1. IP allowlist check
            if not is_ip_allowed(client_ip, role):
                app.logger.warning(
                    f"Access forbidden: {client_ip} is not in {role} allowlist on {request.method} {request.path}"
                )
                log_soc_security_event(
                    "IP_RESTRICTED", client_ip, request.path, "high",
                    f"Client IP not authorized by ALLOWED_{role.upper()}_IPS"
                )
                return jsonify(error="Forbidden: Host IP not authorized"), 403

            # 2. Token configuration check
            expected = get_agent_token() if role == "agent" else get_analyst_token()
            if not expected:
                app.logger.warning(
                    f"Authentication rejected on {request.method} {request.path}: "
                    f"{role} authentication is not configured on the SOC backend (missing token)"
                )
                return jsonify(error=f"{role} auth not configured"), 503

            # 3. Token extraction
            header = request.headers.get("Authorization", "")
            token = header[7:].strip() if header.startswith("Bearer ") else ""
            if not token and not header:
                token = request.headers.get("X-API-Key", "").strip()

            # 4. Token validation before consuming authenticated rate limit
            # Unauthenticated requests are throttled separately so they cannot exhaust authenticated agent quota
            unauth_limit = int(app.config.get("SOC_UNAUTH_RATE_LIMIT_PER_MINUTE") or os.getenv("SOC_UNAUTH_RATE_LIMIT_PER_MINUTE", "60"))
            if not token:
                unauth_allowed, _, retry_after = unauth_rate_limiter.is_allowed(client_ip, unauth_limit)
                if not unauth_allowed:
                    resp = jsonify(error="Rate limit exceeded for unauthenticated requests. Please authenticate.")
                    resp.headers["Retry-After"] = str(int(retry_after))
                    return resp, 429

                app.logger.warning(
                    f"Authentication failed on {request.method} {request.path} from {client_ip}: "
                    f"Missing or malformed Authorization header (expected Bearer token)"
                )
                log_soc_security_event(
                    "UNAUTHORIZED_ACCESS", client_ip, request.path, "low",
                    f"Missing or malformed Authorization header for {role}"
                )
                return jsonify(error="Unauthorized"), 401

            if not secrets.compare_digest(token, expected):
                unauth_allowed, _, retry_after = unauth_rate_limiter.is_allowed(client_ip, unauth_limit)
                if not unauth_allowed:
                    resp = jsonify(error="Rate limit exceeded for unauthenticated requests.")
                    resp.headers["Retry-After"] = str(int(retry_after))
                    return resp, 429

                app.logger.warning(
                    f"Authentication failed on {request.method} {request.path} from {client_ip}: "
                    f"Invalid {role} token supplied (length: {len(token)})"
                )
                log_soc_security_event(
                    "INVALID_TOKEN" if role == "agent" else "FAILED_LOGIN",
                    client_ip, request.path, "medium",
                    f"Invalid {role} token supplied (length: {len(token)})"
                )
                return jsonify(error="Unauthorized"), 401

            # 5. Authenticated rate limit check: only authenticated callers consume this quota
            limit = int(app.config.get("SOC_RATE_LIMIT_PER_MINUTE") or os.getenv("SOC_RATE_LIMIT_PER_MINUTE", "600"))
            allowed, count, retry_after = rate_limiter.is_allowed(client_ip, limit)
            if not allowed:
                app.logger.warning(
                    f"Rate limit exceeded on {request.method} {request.path} from {client_ip} ({count}/{limit})"
                )
                log_soc_security_event(
                    "RATE_LIMIT_EXCEEDED", client_ip, request.path, "medium",
                    f"Exceeded {limit} req/min; retry after {retry_after}s"
                )
                resp = jsonify(error="Rate limit exceeded. Please throttle requests.")
                resp.headers["Retry-After"] = str(int(retry_after))
                return resp, 429

            return fn(*a, **kw)
        return inner
    return deco

def is_management_ip(raw_ip: str) -> bool:
    """Check if IPv4 address belongs to dashboard management listener, loopback, or protected set."""
    try:
        ip = ipaddress.ip_address(raw_ip)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
            return True
        bind_host = get_bind_host()
        if bind_host and bind_host not in ("0.0.0.0", "::"):
            try:
                if ip == ipaddress.ip_address(bind_host):
                    return True
            except ValueError:
                try:
                    for res in socket.getaddrinfo(bind_host, None, socket.AF_INET):
                        if ip == ipaddress.ip_address(res[4][0]):
                            return True
                except Exception:
                    pass
        prot = app.config.get("PROTECTED_IPS") or os.getenv("PROTECTED_IPS", "")
        if prot:
            for item in str(prot).split(","):
                item = item.strip()
                if item:
                    try:
                        if "/" in item:
                            if ip in ipaddress.ip_network(item, strict=False):
                                return True
                        else:
                            if ip == ipaddress.ip_address(item):
                                return True
                    except ValueError:
                        try:
                            for res in socket.getaddrinfo(item, None, socket.AF_INET):
                                if ip == ipaddress.ip_address(res[4][0]):
                                    return True
                        except Exception:
                            pass
    except Exception:
        pass
    return False

def valid_ip(raw):
    if not raw or not isinstance(raw, str):
        raise ValueError("Expected non-empty string for IPv4 address")
    ip = ipaddress.ip_address(raw.strip())
    if not isinstance(ip, ipaddress.IPv4Address) or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        raise ValueError("Expected non-special IPv4 address")
    return str(ip)

def enqueue(target, kind, actor, timeout=None, incident_id=None, message=""):
    target = valid_ip(target)
    if is_management_ip(target) and kind == "BLOCK_IP":
        raise ValueError(f"Cannot block target IP '{target}': management connection is protected")
    valid_kinds = ("BLOCK_IP", "UNBLOCK_IP", "RATE_LIMIT", "APP_REJECT", "AUTH_THROTTLE", "LOG_MONITOR")
    if kind not in valid_kinds: raise ValueError("Unsupported action")
    if timeout is not None and not 1 <= int(timeout) <= 604800: raise ValueError("Timeout must be 1 second to 7 days")
    with db() as c:
        cur = c.execute("""INSERT INTO response_actions
          (incident_id,target_ip,action_type,status,triggered_by,created_at,timeout_seconds,message)
          VALUES(?,?,?,'PENDING',?,?,?,?)""", (incident_id,target,kind,actor,now(),timeout,message))
        return cur.lastrowid

@app.get("/")
def index():
    dry = is_soar_dry_run()
    return render_template(
        "index.html",
        soar_dry_run=dry,
        soar_mode="DRY-RUN" if dry else "ENFORCEMENT"
    )

@app.get("/api/health")
def health():
    dry = is_soar_dry_run()
    return jsonify(
        status="ok",
        timestamp=now(),
        soar_mode="DRY-RUN" if dry else "ENFORCEMENT",
        soar_dry_run=dry
    )

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
                    "SELECT event_id, incident_id, mitre_id, signature, classification_type, detection_method FROM alerts WHERE event_id=?",
                    (event_id,)
                ).fetchone()
                if existing:
                    app.logger.info(f"Duplicate event_id '{event_id}' safely deduplicated (idempotent)")
                    record_ingestion_metric(source, "DEDUPLICATED", event_id)
                    return jsonify(
                        status="accepted",
                        event_id=existing["event_id"],
                        mitre_id=existing["mitre_id"],
                        signature=existing["signature"],
                        incident_id=existing["incident_id"],
                        classification_type=existing["classification_type"] or "known_attack",
                        detection_method=existing["detection_method"] or "rule"
                    ), 202
        except sqlite3.Error as e:
            record_ingestion_metric(source, "FAILED", event_id, str(e))
            return jsonify(error=f"Database persistence error: {str(e)}"), 500

    # Classification & Detection Method Initialization
    raw_class_type = d.get("classification_type") or d.get("category") or ""
    explicit_class_type = str(raw_class_type).lower().strip() if raw_class_type else ""
    classification_type = "known_attack"
    detection_method = str(d.get("detection_method") or "rule").lower().strip()
    mitre = None

    # Handle Directory Discovery (DIR_FUZZ) & HTTP 404 Probing Logic
    is_dir_fuzz_candidate = (
        cleaned_sig in ("HTTP_404", "NOT_FOUND", "404", "DIR_PROBE", "DIRECTORY_DISCOVERY", "SUSPICIOUS_PATH")
        or (cleaned_sig in ("DIR_FUZZ", "DIR_FUZZING", "DIRECTORY_FUZZ", "DIRECTORY_FUZZING", "DIRECTORY_BRUTEFORCE", "DIR-FUZZ") and requested_path)
    )

    if is_dir_fuzz_candidate:
        # False-positive safeguard: exclude benign assets
        if is_benign_path(requested_path):
            app.logger.info(f"Benign path probe '{requested_path}' from {source} ignored (false-positive safeguard)")
            record_ingestion_metric(source, "SUPPRESSED_BENIGN", event_id)
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
                record_ingestion_metric(source, "SUCCESS", event_id, "404 probe recorded below threshold")
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
        mitre = REGISTRY[sig][0]
        classification_type = "known_attack"
        detection_method = "rule"
    else:
        # Check standard registered attack aliases first
        mapped_sig = EVENT_NORMALIZATION.get(cleaned_sig)
        if mapped_sig and mapped_sig in REGISTRY:
            sig = mapped_sig
            mitre = REGISTRY[sig][0]
            classification_type = "known_attack"
            detection_method = str(d.get("detection_method") or "rule").lower().strip()
            raw_sev = d.get("severity", "medium")
        else:
            # Check if event is explicitly or structurally an anomaly or unknown
            is_anomaly_candidate = (
                explicit_class_type == "suspicious_anomaly"
                or any(k in cleaned_sig for k in ("ANOMALY", "BURST", "SUSPICIOUS", "OUTLIER", "SSRF", "TAMPER"))
                or d.get("anomaly_score") is not None
            )
            is_unknown_candidate = (
                explicit_class_type == "unknown"
                or cleaned_sig in ("UNKNOWN", "UNCLASSIFIED", "UNKNOWN_EVENT")
            )

            if is_anomaly_candidate:
                sig = cleaned_sig
                mitre = d.get("mitre_id") or None
                classification_type = "suspicious_anomaly"
                detection_method = str(d.get("detection_method") or "statistical_anomaly").lower().strip()
                raw_sev = d.get("severity", "medium")
            elif is_unknown_candidate:
                sig = cleaned_sig
                mitre = None
                classification_type = "unknown"
                detection_method = str(d.get("detection_method") or "heuristic").lower().strip()
                raw_sev = d.get("severity", "low")
            else:
                # Evaluate via modular ML engine if enabled
                ml_res = ml_engine.evaluate(d) if ml_engine else None
                if ml_res and ml_res.classification_type in ("known_attack", "suspicious_anomaly") and not ml_res.is_ood and ml_res.confidence >= 0.70:
                    sig = ml_res.predicted_category
                    mitre = ml_res.mitre_technique
                    classification_type = ml_res.classification_type
                    detection_method = "ml_model"
                    raw_sev = d.get("severity", "high" if ml_res.anomaly_score > 0.8 else "medium")
                else:
                    app.logger.warning(f"Ingestion rejected from {source}: Unsupported signature '{raw_sig}'")
                    record_ingestion_metric(source, "FAILED", event_id, f"Unsupported signature '{raw_sig}'")
                    log_soc_security_event("MALFORMED_PAYLOAD", source, request.path, "low", f"Unsupported signature '{raw_sig}'")
                    return jsonify(
                        error=f"Unsupported signature '{raw_sig}'. Must map to registered detection types: {list(REGISTRY.keys())}"
                    ), 400

    # Validate severity
    if not isinstance(raw_sev, str):
        return jsonify(error="Field 'severity' must be a string"), 400
    severity = raw_sev.lower().strip()
    if severity not in ("info", "low", "medium", "high", "critical"):
        app.logger.warning(f"Ingestion rejected from {source}: Invalid severity '{raw_sev}'")
        record_ingestion_metric(source, "FAILED", event_id, f"Invalid severity '{raw_sev}'")
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
        tech_label = REGISTRY[sig][1] if sig in REGISTRY else sig
        msg = f"{tech_label} probe detected ({'; '.join(details)})"[:2048]
    else:
        msg = ""

    # Extract rich metadata and destination evidence from Secure Portal
    raw_meta = d.get("metadata")
    if isinstance(raw_meta, dict):
        metadata_json = json.dumps(raw_meta)
        dst_ip = str(d.get("destination_ip") or raw_meta.get("target_ip") or raw_meta.get("destination_ip") or "")[:64] or None
        raw_dport = d.get("destination_port") or raw_meta.get("destination_port") or raw_meta.get("port")
        try:
            dst_port = int(raw_dport) if raw_dport is not None else None
        except (ValueError, TypeError):
            dst_port = None
        protocol = str(d.get("protocol") or raw_meta.get("protocol") or "TCP")[:10]
    else:
        metadata_json = None
        dst_ip = str(d.get("destination_ip") or "")[:64] or None
        try:
            dst_port = int(d.get("destination_port")) if d.get("destination_port") is not None else None
        except (ValueError, TypeError):
            dst_port = None
        protocol = str(d.get("protocol") or "TCP")[:10]

    # Model and anomaly evaluation fields
    confidence = None
    if "confidence" in d:
        try:
            c_val = float(d["confidence"])
            if 0.0 <= c_val <= 1.0:
                confidence = c_val
        except (ValueError, TypeError):
            pass

    anomaly_score = None
    if "anomaly_score" in d:
        try:
            a_val = float(d["anomaly_score"])
            if 0.0 <= a_val <= 1.0:
                anomaly_score = a_val
        except (ValueError, TypeError):
            pass

    model_name = str(d.get("model_name") or "")[:64] or None
    model_version = str(d.get("model_version") or "")[:32] or None
    if not model_name and detection_method == "ml_model":
        model_name = "SOCML-Orchestrator"
        model_version = "1.0.0"

    measurement_window = None
    if "measurement_window_seconds" in d or "window_seconds" in d:
        try:
            measurement_window = int(d.get("measurement_window_seconds") or d.get("window_seconds"))
        except (ValueError, TypeError):
            pass

    threshold_val = None
    if "threshold_value" in d or "threshold" in d:
        try:
            threshold_val = float(d.get("threshold_value") or d.get("threshold"))
        except (ValueError, TypeError):
            pass

    observed_val = None
    if "observed_value" in d or "observed" in d:
        try:
            observed_val = float(d.get("observed_value") or d.get("observed"))
        except (ValueError, TypeError):
            pass

    try:
        with db() as c:
            # 1. Insert alert with extended classification, telemetry, and evidence columns
            c.execute("""INSERT OR IGNORE INTO alerts
              (event_id,source_ip,signature,severity,timestamp,message,mitre_id,
               http_method,requested_path,response_status,detection_reason,
               metadata_json,destination_ip,destination_port,protocol,
               classification_type,detection_method,confidence,anomaly_score,
               model_name,model_version,status,analyst_disposition,
               measurement_window_seconds,threshold_value,observed_value)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new',NULL,?,?,?)""",
              (event_id, source, sig, severity, ts, msg, mitre,
               http_method if requested_path else None,
               requested_path if requested_path else None,
               response_status,
               detection_reason if detection_reason else None,
               metadata_json, dst_ip, dst_port, protocol,
               classification_type, detection_method, confidence, anomaly_score,
               model_name, model_version, measurement_window, threshold_val, observed_val))

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
                """, (inc_id, now(), f"Correlated alert {event_id} ({severity}, {classification_type}): {msg[:120]}"))
                app.logger.info(f"Correlated {sig} alert ({event_id}, severity={severity}) from {source} into existing incident #{inc_id}")
            else:
                if sig in REGISTRY:
                    tech_name = REGISTRY[sig][1]
                    title = f"{tech_name} detected from {source}"
                elif classification_type == "suspicious_anomaly":
                    title = f"Suspicious Anomaly ({sig}) from {source}"
                else:
                    title = f"Unclassified Telemetry ({sig}) from {source}"

                cur_inc = c.execute("""
                    INSERT INTO incidents (title, status, severity, source_ip, signature, mitre_id, created_at, updated_at, defense_status)
                    VALUES (?, 'NEW', ?, ?, ?, ?, ?, ?, 'Detected')
                """, (title, severity, source, sig, mitre, ts, now()))
                inc_id = cur_inc.lastrowid
                c.execute("UPDATE alerts SET incident_id = ? WHERE event_id = ?", (inc_id, event_id))
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SYSTEM', ?, ?, 'SYSTEM')
                """, (inc_id, now(), f"Incident opened from alert {event_id} ({severity}, {classification_type}): {msg[:120]}"))
                app.logger.info(f"Opened new incident #{inc_id} from {sig} alert ({event_id}, severity={severity}) from {source}")

            record_ingestion_metric(source, "SUCCESS", event_id, c=c)

    except sqlite3.Error as e:
        record_ingestion_metric(source, "FAILED", event_id, str(e))
        return jsonify(error=f"Database persistence error: {str(e)}"), 500

    return jsonify(
        status="accepted",
        event_id=event_id,
        mitre_id=mitre,
        signature=sig,
        incident_id=inc_id,
        classification_type=classification_type,
        detection_method=detection_method,
        confidence=confidence,
        anomaly_score=anomaly_score
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
    d = request.get_json(silent=True) or {}
    try:
        aid = int(d["action_id"])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="Valid action_id required"), 400

    state = str(d.get("status", "")).upper().strip()
    if state == "VERIFIED":
        return jsonify(error="Agent cannot directly mark action as VERIFIED; actions must be verified via the verification endpoint with authentic proof"), 400

    if state not in ("EXECUTED", "FAILED", "DRY_RUN", "MITIGATION_APPLIED"):
        return jsonify(error="Invalid status"), 400

    client_ip = request.remote_addr or "127.0.0.1"

    with db() as c:
        action = c.execute("SELECT * FROM response_actions WHERE action_id=?", (aid,)).fetchone()
        if not action:
            return jsonify(error="Action not found or not approved"), 404

        act_dict = dict(action)

        # Validate target_ip if provided
        req_ip = d.get("target_ip")
        if req_ip and str(req_ip).strip() != act_dict["target_ip"]:
            log_soc_security_event(
                "MALFORMED_PAYLOAD", client_ip, request.path, "high",
                f"Mismatched target IP in agent report: {req_ip} != {act_dict['target_ip']}"
            )
            return jsonify(error=f"Target IP mismatch: request target_ip '{req_ip}' does not match action target_ip '{act_dict['target_ip']}'"), 400

        # Validate action_type if provided
        req_type = d.get("action_type")
        if req_type and str(req_type).upper().strip() != str(act_dict["action_type"]).upper().strip():
            return jsonify(error=f"Action type mismatch: request action_type '{req_type}' does not match action action_type '{act_dict['action_type']}'"), 400

        # Validate state transitions
        current_st = act_dict["status"]
        if current_st in ("CANCELLED", "EXPIRED"):
            return jsonify(error=f"Cannot transition action #{aid} from terminal state '{current_st}'"), 409

        if current_st == state:
            return jsonify(status="acknowledged", idempotent=True)

        if current_st not in ("APPROVED", "VERIFICATION_PENDING"):
            return jsonify(error="Action not found or not approved"), 404

        # Attach evidence if provided without marking as verified
        ev_payload = d.get("evidence") or d.get("verification_evidence")
        ev_json = None
        if ev_payload is not None:
            ev_json = json.dumps(ev_payload) if isinstance(ev_payload, dict) else str(ev_payload)

        msg = str(d.get("message", ""))[:500]
        if ev_json:
            c.execute("""UPDATE response_actions SET status=?, executed_at=?, message=?, verification_evidence=?
              WHERE action_id=?""", (state, now(), msg, ev_json, aid))
        else:
            c.execute("""UPDATE response_actions SET status=?, executed_at=?, message=?
              WHERE action_id=?""", (state, now(), msg, aid))

        inc_id = act_dict.get("incident_id")
        if inc_id:
            if state in ("EXECUTED", "MITIGATION_APPLIED"):
                def_st = "Mitigation Applied"
            elif state == "FAILED":
                def_st = "Verification Failed"
            else:
                def_st = "Detected"
            c.execute("UPDATE incidents SET defense_status=?, updated_at=? WHERE incident_id=?", (def_st, now(), inc_id))
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SYSTEM', ?, ?, 'CONTAINMENT_REQUEST')
            """, (inc_id, now(), f"Agent reported action #{aid} status as {state}. Message: {msg[:120]}"))

    return jsonify(status="acknowledged")

@app.post("/api/agent/response-actions/<int:aid>/evidence")
@auth("agent")
def submit_agent_verification_evidence(aid):
    """Allow remediator agent to submit authentic host firewall verification evidence."""
    d = request.get_json(silent=True) or {}
    client_ip = request.remote_addr or "127.0.0.1"

    with db() as c:
        action = c.execute("SELECT * FROM response_actions WHERE action_id=?", (aid,)).fetchone()
        if not action:
            return jsonify(error="Action not found"), 404

        act_dict = dict(action)
        if d.get("target_ip") and str(d["target_ip"]).strip() != act_dict["target_ip"]:
            log_soc_security_event(
                "MALFORMED_PAYLOAD", client_ip, request.path, "high",
                f"Mismatched target IP in agent evidence submission: {d.get('target_ip')} != {act_dict['target_ip']}"
            )
            return jsonify(error="Target IP mismatch: evidence target_ip does not match action target_ip"), 400

        if d.get("action_type") and str(d["action_type"]).upper().strip() != str(act_dict["action_type"]).upper().strip():
            return jsonify(error="Action type mismatch: evidence action_type does not match action action_type"), 400

        ev_json = json.dumps(d) if isinstance(d, dict) else str(d)
        c.execute("UPDATE response_actions SET verification_evidence=? WHERE action_id=?", (ev_json, aid))

        inc_id = act_dict.get("incident_id")
        if inc_id:
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SYSTEM', ?, ?, 'CONTAINMENT_REQUEST')
            """, (inc_id, now(), f"Remediator submitted host verification evidence for action #{aid}."))

    return jsonify(status="accepted", action_id=aid)

@app.post("/api/soc/mitigate/block")
@auth("analyst")
def block():
    d = request.get_json(silent=True) or {}
    inc_id = d.get("incident_id")
    target_ip = d.get("target_ip")
    if not target_ip:
        return jsonify(error="Field 'target_ip' is required"), 400

    # Determine signature from incident if available, or direct field
    sig = d.get("signature")
    if inc_id and not sig:
        with db() as c:
            row = c.execute("SELECT signature, source_ip FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()
            if row:
                sig = row["signature"]
                if not target_ip:
                    target_ip = row["source_ip"]

    policy = get_response_policy(sig) if sig else None

    # If apply_policy is explicitly requested and policy is not supported
    if d.get("apply_policy") and policy and not policy["is_supported"]:
        reason = policy.get("pending_reason") or f"Application instrumentation for {policy['signature']} pending deployment"
        timeout_val = policy.get("duration_seconds")
        try:
            target_clean = valid_ip(target_ip)
        except Exception as e:
            return jsonify(error=str(e)), 400

        with db() as c:
            cur = c.execute("""
                INSERT INTO response_actions
                (incident_id, target_ip, action_type, status, triggered_by, created_at, timeout_seconds, message)
                VALUES (?, ?, ?, 'PENDING_IMPLEMENTATION', 'SOC_ANALYST', ?, ?, ?)
            """, (inc_id, target_clean, policy["action_type"], now(), timeout_val, reason))
            aid = cur.lastrowid

            if inc_id:
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Response policy evaluated for {policy['signature']}: {policy['selected_response']}. Action #{aid} marked PENDING_IMPLEMENTATION ({reason})."))

        return jsonify(
            status="PENDING_IMPLEMENTATION",
            action_id=aid,
            incident_id=inc_id,
            supported=False,
            policy=policy,
            message=reason
        ), 200

    # For supported network policies, use timeout from policy if not given
    timeout_sec = d.get("timeout_seconds")
    if timeout_sec is None and policy and policy.get("duration_seconds"):
        timeout_sec = policy["duration_seconds"]

    try:
        aid = enqueue(target_ip, "BLOCK_IP", "SOC_ANALYST", timeout_sec, inc_id, policy["policy_name"] if policy else "")
    except (KeyError, ValueError, TypeError) as e:
        return jsonify(error=str(e)), 400

    if inc_id:
        try:
            with db() as c:
                c.execute("""
                    UPDATE incidents SET status = 'CONTAINMENT_PENDING_APPROVAL', updated_at = ?
                    WHERE incident_id = ?
                """, (now(), inc_id))
                policy_note = f" (Policy: {policy['selected_response']})" if policy else ""
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Containment BLOCK_IP action #{aid} queued for target {target_ip}{policy_note}. Status: PENDING_APPROVAL"))
        except Exception:
            pass

    return jsonify(status="PENDING_APPROVAL", action_id=aid, incident_id=inc_id, policy=policy), 202

@app.post("/api/soc/mitigate/apply-policy")
@auth("analyst")
def apply_policy_action():
    d = request.get_json(silent=True) or {}
    inc_id = d.get("incident_id")
    target_ip = d.get("target_ip")
    sig = d.get("signature")

    if inc_id and not (target_ip and sig):
        with db() as c:
            row = c.execute("SELECT signature, source_ip FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()
            if row:
                sig = sig or row["signature"]
                target_ip = target_ip or row["source_ip"]

    if not target_ip:
        return jsonify(error="Field 'target_ip' is required"), 400

    policy = get_response_policy(sig)

    if not policy["is_supported"]:
        reason = policy.get("pending_reason") or f"Application instrumentation for {policy['signature']} pending deployment"
        timeout_val = policy.get("duration_seconds")
        try:
            target_clean = valid_ip(target_ip)
        except Exception as e:
            return jsonify(error=str(e)), 400

        with db() as c:
            cur = c.execute("""
                INSERT INTO response_actions
                (incident_id, target_ip, action_type, status, triggered_by, created_at, timeout_seconds, message)
                VALUES (?, ?, ?, 'PENDING_IMPLEMENTATION', 'SOC_ANALYST', ?, ?, ?)
            """, (inc_id, target_clean, policy["action_type"], now(), timeout_val, reason))
            aid = cur.lastrowid

            if inc_id:
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Policy {policy['policy_name']} evaluated: {policy['selected_response']}. Action #{aid} marked PENDING_IMPLEMENTATION ({reason})."))

        return jsonify(
            status="PENDING_IMPLEMENTATION",
            action_id=aid,
            incident_id=inc_id,
            supported=False,
            policy=policy,
            message=reason
        ), 200

    timeout_sec = d.get("timeout_seconds") or policy.get("duration_seconds")
    try:
        aid = enqueue(target_ip, policy.get("action_type", "BLOCK_IP"), "SOC_ANALYST", timeout_sec, inc_id, policy["policy_name"])
    except (KeyError, ValueError, TypeError) as e:
        return jsonify(error=str(e)), 400

    if inc_id:
        try:
            with db() as c:
                c.execute("UPDATE incidents SET status = 'CONTAINMENT_PENDING_APPROVAL', updated_at = ? WHERE incident_id = ?", (now(), inc_id))
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Containment action #{aid} ({policy['selected_response']}) queued for target {target_ip}. Status: PENDING_APPROVAL"))
        except Exception:
            pass

    return jsonify(status="PENDING_APPROVAL", action_id=aid, incident_id=inc_id, supported=True, policy=policy), 202

@app.get("/api/soc/response-policies")
@auth("analyst")
def list_response_policies():
    return jsonify(
        status="success",
        policies=RESPONSE_POLICIES,
        fallback_policy=SAFE_FALLBACK_POLICY,
        supported_signatures=[k for k, v in RESPONSE_POLICIES.items() if v.get("is_supported")],
        soar_mode=get_soar_mode(),
        soar_dry_run=is_soar_dry_run()
    )

@app.get("/api/soc/response-policies/<signature>")
@auth("analyst")
def get_signature_response_policy(signature):
    pol = get_response_policy(signature)
    return jsonify(
        status="success",
        signature=signature,
        policy=pol,
        soar_mode=get_soar_mode(),
        soar_dry_run=is_soar_dry_run()
    )

@app.post("/api/soc/mitigate/unblock")
@auth("analyst")
def unblock():
    d = request.get_json(silent=True) or {}
    inc_id = d.get("incident_id")
    try:
        aid = enqueue(d["target_ip"], "UNBLOCK_IP", "SOC_ANALYST", None, inc_id)
    except (KeyError, ValueError, TypeError) as e:
        return jsonify(error=str(e)), 400

    if inc_id:
        try:
            with db() as c:
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Rollback UNBLOCK_IP action #{aid} queued for target {d['target_ip']}. Status: PENDING_APPROVAL"))
        except Exception:
            pass

    return jsonify(status="PENDING_APPROVAL", action_id=aid, incident_id=inc_id), 202

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
    return jsonify(status="APPROVED", action_id=aid)

@app.post("/api/soc/response-actions/<int:aid>/pending-verification")
@auth("analyst")
def mark_pending_verification(aid):
    with db() as c:
        action = c.execute("SELECT * FROM response_actions WHERE action_id=?", (aid,)).fetchone()
        if not action:
            return jsonify(error="Action not found"), 404
        if action["status"] not in ("EXECUTED", "MITIGATION_APPLIED", "APPROVED"):
            return jsonify(error="Action must be in EXECUTED, MITIGATION_APPLIED, or APPROVED status to request verification"), 400
        c.execute("UPDATE response_actions SET status='VERIFICATION_PENDING' WHERE action_id=?", (aid,))
        inc_id = action["incident_id"]
        if inc_id:
            c.execute("UPDATE incidents SET defense_status='Verification Pending', updated_at=? WHERE incident_id=?", (now(), inc_id))
    return jsonify(status="VERIFICATION_PENDING", action_id=aid)

@app.post("/api/soc/response-actions/<int:aid>/verify")
@auth("analyst")
def verify_action(aid):
    d = request.get_json(silent=True) or {}
    with db() as c:
        check_and_update_expired_controls(c)
        action = c.execute(
            "SELECT * FROM response_actions WHERE action_id=?", (aid,)
        ).fetchone()
        if not action:
            return jsonify(error="Action not found"), 404

        act_dict = dict(action)
        is_valid, reason, structured_ev = validate_verification_evidence(act_dict, d)

        if not is_valid:
            ev_json = json.dumps(structured_ev) if structured_ev else json.dumps({"error": reason})
            c.execute("""
                UPDATE response_actions
                SET status = 'VERIFICATION_FAILED', verification_evidence = ?
                WHERE action_id = ?
            """, (ev_json, aid))
            inc_id = act_dict.get("incident_id")
            if inc_id:
                c.execute("""
                    UPDATE incidents
                    SET defense_status = 'Verification Failed', updated_at = ?
                    WHERE incident_id = ?
                """, (now(), inc_id))
                c.execute("""
                    INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                    VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
                """, (inc_id, now(), f"Containment verification FAILED for action #{aid} on target {act_dict['target_ip']}. Reason: {reason}"))
            return jsonify(
                status="VERIFICATION_FAILED",
                action_id=aid,
                verified=False,
                error=reason,
                message=reason
            ), 200

        ev_json = json.dumps(structured_ev)
        c.execute("""
            UPDATE response_actions
            SET status = 'VERIFIED', verification_evidence = ?, verified_at = ?, message = ?
            WHERE action_id = ?
        """, (ev_json, now(), reason[:500], aid))
        inc_id = act_dict.get("incident_id")
        if inc_id:
            c.execute("""
                UPDATE incidents
                SET status = 'CONTAINED', defense_status = 'Verified', verification_evidence = ?, updated_at = ?
                WHERE incident_id = ?
            """, (ev_json, now(), inc_id))
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SOC_ANALYST', ?, ?, 'CONTAINMENT_REQUEST')
            """, (inc_id, now(), f"Containment action #{aid} verified against host nftables. Status: VERIFIED. Evidence: {reason[:120]}"))

    return jsonify(
        status="VERIFIED",
        action_id=aid,
        verified=True,
        evidence=structured_ev
    ), 200

@app.get("/api/soc/response-actions")
@auth("analyst")
def list_response_actions():
    status_filter = request.args.get("status", "").upper().strip()
    target_filter = request.args.get("target_ip", "").strip()
    inc_filter = request.args.get("incident_id")
    temp_filter = request.args.get("temporary")

    with db() as c:
        check_and_update_expired_controls(c)
        query = "SELECT * FROM response_actions WHERE 1=1"
        params = []
        if status_filter and status_filter != "ALL":
            query += " AND status = ?"
            params.append(status_filter)
        if target_filter:
            query += " AND target_ip = ?"
            params.append(target_filter)
        if inc_filter:
            try:
                query += " AND incident_id = ?"
                params.append(int(inc_filter))
            except (ValueError, TypeError):
                pass
        if temp_filter and temp_filter in ("1", "true", "yes"):
            query += " AND timeout_seconds IS NOT NULL AND timeout_seconds > 0"

        query += " ORDER BY action_id DESC"
        rows = c.execute(query, params).fetchall()

        actions = []
        active_temp_count = 0
        expired_count = 0
        verified_count = 0

        for r in rows:
            act = dict(r)
            is_expired, remaining, expires_iso = compute_action_expiry(act)
            act["is_expired"] = is_expired
            act["time_remaining_seconds"] = remaining
            act["expires_at"] = expires_iso
            act["is_temporary"] = bool(act.get("timeout_seconds") and int(act["timeout_seconds"]) > 0)

            st = act.get("status", "")
            is_dry = (st == "DRY_RUN" or any(k in (act.get("message") or "").lower() for k in ("dry_run", "dry-run", "dry run", "simulat")))
            act["is_dry_run"] = is_dry
            act["enforcement_type"] = "SIMULATED" if is_dry else "REAL"

            if is_expired or st == "EXPIRED":
                act["defense_status"] = "Expired"
                expired_count += 1
            elif st == "VERIFIED":
                act["defense_status"] = "Verified"
                verified_count += 1
                if act["is_temporary"]:
                    active_temp_count += 1
            elif st == "VERIFICATION_FAILED":
                act["defense_status"] = "Verification Failed"
            elif st == "VERIFICATION_PENDING":
                act["defense_status"] = "Verification Pending"
            elif st in ("EXECUTED", "MITIGATION_APPLIED"):
                act["defense_status"] = "Mitigation Applied"
            elif st in ("PENDING", "APPROVED"):
                act["defense_status"] = "Verification Pending"
            else:
                act["defense_status"] = "Detected"

            if act.get("verification_evidence"):
                try:
                    act["evidence_parsed"] = json.loads(act["verification_evidence"])
                except Exception:
                    act["evidence_parsed"] = {"raw": act["verification_evidence"]}
            else:
                act["evidence_parsed"] = None

            actions.append(act)

    return jsonify(
        status="success",
        count=len(actions),
        actions=actions,
        active_temporary_controls_count=active_temp_count,
        expired_controls_count=expired_count,
        verified_count=verified_count,
        soar_mode=get_soar_mode(),
        soar_dry_run=is_soar_dry_run()
    )

@app.get("/api/soc/temporary-controls")
@auth("analyst")
def list_temporary_controls():
    with db() as c:
        check_and_update_expired_controls(c)
        rows = c.execute("""
            SELECT * FROM response_actions
            WHERE timeout_seconds IS NOT NULL AND timeout_seconds > 0
            ORDER BY action_id DESC
        """).fetchall()

        active = []
        expired = []
        for r in rows:
            act = dict(r)
            is_expired, remaining, expires_iso = compute_action_expiry(act)
            act["is_expired"] = is_expired
            act["time_remaining_seconds"] = remaining
            act["expires_at"] = expires_iso
            act["is_temporary"] = True
            is_dry = (act.get("status") == "DRY_RUN" or any(k in (act.get("message") or "").lower() for k in ("dry_run", "dry-run", "dry run", "simulat")))
            act["is_dry_run"] = is_dry
            act["enforcement_type"] = "SIMULATED" if is_dry else "REAL"
            if is_expired or act.get("status") == "EXPIRED":
                act["defense_status"] = "Expired"
                expired.append(act)
            else:
                st = act.get("status", "")
                if st == "VERIFIED":
                    act["defense_status"] = "Verified"
                elif st == "VERIFICATION_FAILED":
                    act["defense_status"] = "Verification Failed"
                elif st in ("EXECUTED", "MITIGATION_APPLIED"):
                    act["defense_status"] = "Mitigation Applied"
                else:
                    act["defense_status"] = "Verification Pending"
                active.append(act)

    return jsonify(
        status="success",
        active_count=len(active),
        expired_count=len(expired),
        active_controls=active,
        expired_controls=expired,
        soar_mode=get_soar_mode(),
        soar_dry_run=is_soar_dry_run()
    )

@app.get("/api/soc/mitre-matrix")
@auth("analyst")
def matrix():
    items = []
    with db() as c:
        check_and_update_expired_controls(c)
        for sig, (tid, name, tactic) in REGISTRY.items():
            count = c.execute("SELECT COUNT(*) FROM alerts WHERE signature=?", (sig,)).fetchone()[0]
            # VERIFIED must be set only after independent confirmation of the host nft set.
            # Expired actions are excluded from the verified mitigation count!
            mitigated = c.execute("""
                SELECT COUNT(DISTINCT r.action_id) FROM response_actions r
                LEFT JOIN incidents i ON r.incident_id = i.incident_id
                WHERE r.action_type = 'BLOCK_IP'
                  AND r.status = 'VERIFIED'
                  AND (
                    (r.incident_id IS NOT NULL AND i.signature = ?)
                    OR
                    (r.incident_id IS NULL AND r.target_ip IN (SELECT source_ip FROM alerts WHERE signature = ?))
                  )
            """, (sig, sig)).fetchone()[0]

            latest_action = c.execute("""
                SELECT r.status, r.timeout_seconds, r.executed_at, r.created_at FROM response_actions r
                LEFT JOIN incidents i ON r.incident_id = i.incident_id
                WHERE (
                    (r.incident_id IS NOT NULL AND i.signature = ?)
                    OR
                    (r.incident_id IS NULL AND r.target_ip IN (SELECT source_ip FROM alerts WHERE signature = ?))
                )
                ORDER BY r.action_id DESC LIMIT 1
            """, (sig, sig)).fetchone()

            if count == 0:
                state = "UNTESTED"
                defense_status = "Untested"
            elif mitigated > 0:
                state = "MITIGATED"
                defense_status = "Verified"
            else:
                state = "DETECTED"
                if latest_action:
                    act_st = latest_action["status"]
                    if act_st == "VERIFIED":
                        defense_status = "Verified"
                    elif act_st in ("EXECUTED", "MITIGATION_APPLIED"):
                        defense_status = "Mitigation Applied"
                    elif act_st == "VERIFICATION_PENDING":
                        defense_status = "Verification Pending"
                    elif act_st == "VERIFICATION_FAILED":
                        defense_status = "Verification Failed"
                    elif act_st == "EXPIRED":
                        defense_status = "Expired"
                    else:
                        defense_status = "Detected"
                else:
                    defense_status = "Detected"

            items.append(dict(
                signature=sig,
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                alert_count=count,
                mitigated_count=mitigated,
                state=state,
                defense_status=defense_status
            ))

    # Calculate distinct detected and mitigated MITRE techniques
    distinct_detected_techs = set()
    distinct_mitigated_techs = set()
    for x in items:
        tid = x["technique_id"]
        if x["alert_count"] > 0:
            distinct_detected_techs.add(tid)
        if x["mitigated_count"] > 0 and x["state"] == "MITIGATED":
            distinct_mitigated_techs.add(tid)

    # Mitigated techniques must be a subset of detected techniques
    qualifying_mitigated = distinct_mitigated_techs.intersection(distinct_detected_techs)

    detected_count = len(distinct_detected_techs)
    mitigated_count = len(qualifying_mitigated)

    index = round(mitigated_count / detected_count * 100, 2) if detected_count > 0 else None
    return jsonify(
        status="success",
        matrix=items,
        resilience_index=index,
        detected_techniques=detected_count,
        mitigated_techniques=mitigated_count,
        distinct_detected=list(distinct_detected_techs),
        distinct_mitigated=list(qualifying_mitigated),
        soar_mode=get_soar_mode(),
        soar_dry_run=is_soar_dry_run(),
        note="MITIGATED requires independent verification; execution alone is insufficient."
    )

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
        check_and_update_expired_controls(c)
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
            inc["response_policy"] = get_response_policy(sig)

            # Count alerts
            cnt = c.execute("SELECT COUNT(*) FROM alerts WHERE incident_id = ?", (inc["incident_id"],)).fetchone()[0]
            inc["alert_count"] = cnt

            # Check actions and compute defense status & active temporary controls
            act_rows = c.execute("""
                SELECT action_id, incident_id, target_ip, action_type, status, triggered_by,
                       created_at, executed_at, timeout_seconds, message,
                       verification_evidence, verified_at, expires_at
                FROM response_actions
                WHERE incident_id = ? OR target_ip = ?
                ORDER BY action_id DESC
            """, (inc["incident_id"], inc["source_ip"])).fetchall()

            actions = []
            active_temp = []
            for ar in act_rows:
                ad = dict(ar)
                is_exp, rem, exp_iso = compute_action_expiry(ad)
                ad["is_expired"] = is_exp
                ad["time_remaining_seconds"] = rem
                ad["expires_at"] = exp_iso
                ad["is_temporary"] = bool(ad.get("timeout_seconds") and int(ad["timeout_seconds"]) > 0)
                actions.append(ad)
                if ad["is_temporary"] and not is_exp and ad.get("status") in ("VERIFIED", "EXECUTED", "MITIGATION_APPLIED", "VERIFICATION_PENDING", "APPROVED", "PENDING"):
                    active_temp.append(ad)

            inc["response_actions"] = actions
            inc["latest_action"] = actions[0] if actions else None
            inc["active_temporary_controls"] = active_temp

            def_st, primary_act = resolve_incident_defense_status(inc, actions)
            inc["defense_status"] = def_st

            incidents.append(inc)

    return jsonify(status="success", count=len(incidents), incidents=incidents)

@app.get("/api/soc/incidents/<int:incident_id>")
@auth("analyst")
def get_incident_details(incident_id):
    with db() as c:
        check_and_update_expired_controls(c)
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
        inc["response_policy"] = get_response_policy(sig)

        # Primary and linked alerts
        alert_rows = c.execute("""
            SELECT id, event_id, source_ip, signature, severity, timestamp, message, mitre_id,
                   http_method, requested_path, response_status, detection_reason,
                   metadata_json, destination_ip, destination_port, protocol,
                   classification_type, detection_method, confidence, anomaly_score,
                   model_name, model_version, status, analyst_disposition,
                   measurement_window_seconds, threshold_value, observed_value
            FROM alerts WHERE incident_id = ? ORDER BY id DESC
        """, (incident_id,)).fetchall()
        alerts = [dict(a) for a in alert_rows]

        # Related alerts
        related_rows = c.execute("""
            SELECT id, event_id, source_ip, signature, severity, timestamp, message, mitre_id, incident_id,
                   http_method, requested_path, response_status, detection_reason,
                   metadata_json, destination_ip, destination_port, protocol,
                   classification_type, detection_method, confidence, anomaly_score,
                   model_name, model_version, status, analyst_disposition,
                   measurement_window_seconds, threshold_value, observed_value
            FROM alerts
            WHERE (source_ip = ? OR signature = ?) AND (incident_id IS NULL OR incident_id != ?)
            ORDER BY id DESC LIMIT 15
        """, (inc["source_ip"], sig, incident_id)).fetchall()
        related_alerts = [dict(r) for r in related_rows]

        # Response actions
        action_rows = c.execute("""
            SELECT action_id, incident_id, target_ip, action_type, status, triggered_by,
                   created_at, executed_at, timeout_seconds, message,
                   verification_evidence, verified_at, expires_at
            FROM response_actions
            WHERE incident_id = ? OR target_ip = ?
            ORDER BY action_id DESC
        """, (incident_id, inc["source_ip"])).fetchall()

        actions = []
        active_temp = []
        for ar in action_rows:
            ad = dict(ar)
            is_exp, rem, exp_iso = compute_action_expiry(ad)
            ad["is_expired"] = is_exp
            ad["time_remaining_seconds"] = rem
            ad["expires_at"] = exp_iso
            ad["is_temporary"] = bool(ad.get("timeout_seconds") and int(ad["timeout_seconds"]) > 0)
            st = ad.get("status", "")
            is_dry = (st == "DRY_RUN" or any(k in (ad.get("message") or "").lower() for k in ("dry_run", "dry-run", "dry run", "simulat")))
            ad["is_dry_run"] = is_dry
            ad["enforcement_type"] = "SIMULATED" if is_dry else "REAL"
            if is_exp or st == "EXPIRED":
                ad["defense_status"] = "Expired"
            elif st == "VERIFIED":
                ad["defense_status"] = "Verified"
            elif st == "VERIFICATION_FAILED":
                ad["defense_status"] = "Verification Failed"
            elif st == "VERIFICATION_PENDING":
                ad["defense_status"] = "Verification Pending"
            elif st in ("EXECUTED", "MITIGATION_APPLIED"):
                ad["defense_status"] = "Mitigation Applied"
            elif st in ("PENDING", "APPROVED"):
                ad["defense_status"] = "Verification Pending"
            else:
                ad["defense_status"] = "Detected"

            actions.append(ad)
            if ad["is_temporary"] and not is_exp and st in ("VERIFIED", "EXECUTED", "MITIGATION_APPLIED", "VERIFICATION_PENDING", "APPROVED", "PENDING"):
                active_temp.append(ad)

        def_st, primary_act = resolve_incident_defense_status(inc, actions)
        inc["defense_status"] = def_st
        inc["active_temporary_controls"] = active_temp
        if primary_act and primary_act.get("verification_evidence"):
            inc["verification_evidence"] = primary_act["verification_evidence"]

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
                "detail": f"Status: {act['status']} (Defense Status: {act['defense_status']}; Triggered by {act['triggered_by']})",
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

        timeline.sort(key=lambda x: str(x["timestamp"]))

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
            active_temporary_controls=active_temp,
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
    class_filter = request.args.get("classification_type", "").lower().strip()
    method_filter = request.args.get("detection_method", "").lower().strip()
    status_filter = request.args.get("status", "").lower().strip()
    mitre_filter = request.args.get("mitre_id", "").upper().strip() or request.args.get("technique_id", "").upper().strip()
    from_time = request.args.get("from_time", "").strip()
    to_time = request.args.get("to_time", "").strip()
    search_q = request.args.get("search", "").strip()
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = max(0, int(request.args.get("offset", 0)))

    query = """
        SELECT a.id, a.event_id, a.source_ip, a.signature, a.severity, a.timestamp,
               a.message, a.mitre_id, a.incident_id, a.http_method, a.requested_path,
               a.response_status, a.detection_reason,
               a.metadata_json, a.destination_ip, a.destination_port, a.protocol,
               a.classification_type, a.detection_method, a.confidence, a.anomaly_score,
               a.model_name, a.model_version, a.status, a.analyst_disposition,
               a.measurement_window_seconds, a.threshold_value, a.observed_value,
               i.title AS incident_title, i.status AS incident_status, i.defense_status AS incident_defense_status
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
    if class_filter and class_filter != "all":
        query += " AND a.classification_type = ?"
        params.append(class_filter)
    if method_filter and method_filter != "all":
        query += " AND a.detection_method = ?"
        params.append(method_filter)
    if status_filter and status_filter != "all":
        query += " AND a.status = ?"
        params.append(status_filter)
    if mitre_filter and mitre_filter != "ALL":
        query += " AND a.mitre_id = ?"
        params.append(mitre_filter)
    if from_time:
        query += " AND a.timestamp >= ?"
        params.append(from_time)
    if to_time:
        query += " AND a.timestamp <= ?"
        params.append(to_time)
    if search_q:
        query += " AND (a.source_ip LIKE ? OR a.signature LIKE ? OR a.message LIKE ? OR a.requested_path LIKE ? OR a.detection_reason LIKE ?)"
        pattern = f"%{search_q}%"
        params.extend([pattern, pattern, pattern, pattern, pattern])

    query += " ORDER BY a.id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with db() as c:
        rows = c.execute(query, params).fetchall()
        alerts = []
        for r in rows:
            ad = dict(r)
            sig = ad["signature"]
            reg = REGISTRY.get(sig, (ad["mitre_id"] or None, sig, "Unclassified" if ad["classification_type"] != "known_attack" else "Unknown"))
            ad["technique_id"] = ad["mitre_id"] or reg[0]
            ad["technique_name"] = reg[1] if sig in REGISTRY else (ad["signature"] if ad["classification_type"] == "suspicious_anomaly" else "Unclassified Telemetry")
            ad["tactic"] = reg[2] if sig in REGISTRY else ("Anomaly" if ad["classification_type"] == "suspicious_anomaly" else "Triage")
            ad["classification_type"] = ad.get("classification_type") or "known_attack"
            ad["detection_method"] = ad.get("detection_method") or "rule"
            ad["status"] = ad.get("status") or "new"
            if ad.get("metadata_json"):
                try:
                    ad["metadata"] = json.loads(ad["metadata_json"])
                except Exception:
                    ad["metadata"] = {}
            else:
                ad["metadata"] = {}
            alerts.append(ad)

    return jsonify(status="success", count=len(alerts), alerts=alerts)

@app.get("/api/soc/alerts/<identifier>")
@auth("analyst")
def get_alert_detail(identifier):
    """Retrieve full details, notes, and audit history for a single alert."""
    with db() as c:
        query = """
            SELECT a.*, i.title AS incident_title, i.status AS incident_status, i.defense_status AS incident_defense_status
            FROM alerts a
            LEFT JOIN incidents i ON a.incident_id = i.incident_id
            WHERE a.id = ? OR a.event_id = ?
            LIMIT 1
        """
        row = c.execute(query, (identifier, identifier)).fetchone()
        if not row:
            return jsonify(error="Alert not found"), 404

        ad = dict(row)
        sig = ad["signature"]
        reg = REGISTRY.get(sig, (ad["mitre_id"] or None, sig, "Unclassified"))
        ad["technique_id"] = ad["mitre_id"] or reg[0]
        ad["technique_name"] = reg[1] if sig in REGISTRY else ad["signature"]
        ad["tactic"] = reg[2] if sig in REGISTRY else ("Anomaly" if ad["classification_type"] == "suspicious_anomaly" else "Triage")
        if ad.get("metadata_json"):
            try:
                ad["metadata"] = json.loads(ad["metadata_json"])
            except Exception:
                ad["metadata"] = {}
        else:
            ad["metadata"] = {}

        notes_raw = c.execute("SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY note_id ASC", (ad["id"],)).fetchall()
        notes = []
        for n in notes_raw:
            nd = dict(n)
            nd["note"] = nd["note_text"]
            nd["timestamp"] = nd["created_at"]
            notes.append(nd)
        ad["notes"] = notes

    return jsonify(status="success", alert=ad, notes=notes)

@app.post("/api/soc/alerts/<identifier>/status")
@auth("analyst")
def update_alert_status(identifier):
    """Update analyst disposition for an alert (investigating, confirmed, false_positive, resolved)."""
    d = request.get_json(silent=True) or {}
    new_status = str(d.get("status", "")).lower().strip()
    valid_statuses = ("new", "investigating", "confirmed", "false_positive", "resolved")
    if new_status not in valid_statuses:
        return jsonify(error=f"Invalid status '{new_status}'. Allowed: {list(valid_statuses)}"), 400

    rationale = str(d.get("rationale") or d.get("disposition") or "").strip()[:1000]

    with db() as c:
        row = c.execute("SELECT id, event_id, incident_id, status FROM alerts WHERE id = ? OR event_id = ?", (identifier, identifier)).fetchone()
        if not row:
            return jsonify(error="Alert not found"), 404

        aid = row["id"]
        eid = row["event_id"]
        inc_id = row["incident_id"]
        old_status = row["status"]

        c.execute("""
            UPDATE alerts
            SET status = ?, analyst_disposition = ?
            WHERE id = ?
        """, (new_status, new_status, aid))

        # Add entry to alert_notes
        note_text = f"Analyst changed status from {old_status} to {new_status}."
        if rationale:
            note_text += f" Rationale: {rationale}"

        c.execute("""
            INSERT INTO alert_notes (alert_id, author, created_at, note_text)
            VALUES (?, 'SOC_ANALYST', ?, ?)
        """, (aid, now(), note_text))

        # Correlate note to incident if linked
        if inc_id:
            c.execute("""
                INSERT INTO incident_notes (incident_id, author, created_at, note_text, note_type)
                VALUES (?, 'SOC_ANALYST', ?, ?, 'STATUS_CHANGE')
            """, (inc_id, now(), f"Alert {eid} updated to {new_status}: {rationale[:100]}"))

        # Fetch updated notes
        notes_raw = c.execute("SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY note_id ASC", (aid,)).fetchall()
        notes = []
        for n in notes_raw:
            nd = dict(n)
            nd["note"] = nd["note_text"]
            nd["timestamp"] = nd["created_at"]
            notes.append(nd)

    return jsonify(status="success", alert_id=aid, event_id=eid, new_status=new_status, rationale=rationale, notes=notes)

@app.post("/api/soc/alerts/<identifier>/notes")
@auth("analyst")
def add_alert_note(identifier):
    """Add analyst investigation note directly to an alert."""
    d = request.get_json(silent=True) or {}
    note_text = str(d.get("note") or d.get("note_text") or "").strip()[:2000]
    if not note_text:
        return jsonify(error="Field 'note' is required"), 400

    with db() as c:
        row = c.execute("SELECT id, event_id FROM alerts WHERE id = ? OR event_id = ?", (identifier, identifier)).fetchone()
        if not row:
            return jsonify(error="Alert not found"), 404

        aid = row["id"]
        cur = c.execute("""
            INSERT INTO alert_notes (alert_id, author, created_at, note_text)
            VALUES (?, 'SOC_ANALYST', ?, ?)
        """, (aid, now(), note_text))
        note_id = cur.lastrowid

        notes_raw = c.execute("SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY note_id ASC", (aid,)).fetchall()
        notes = []
        for n in notes_raw:
            nd = dict(n)
            nd["note"] = nd["note_text"]
            nd["timestamp"] = nd["created_at"]
            notes.append(nd)

    return jsonify(status="success", note_id=note_id, alert_id=aid, notes=notes)

@app.get("/api/soc/telemetry/status")
@auth("analyst")
def get_telemetry_status():
    """Report telemetry pipeline health, last receipt timestamp, and ingestion failure history."""
    with db() as c:
        last_success = c.execute("""
            SELECT timestamp FROM ingestion_telemetry
            WHERE status = 'SUCCESS'
            ORDER BY metric_id DESC LIMIT 1
        """).fetchone()

        total_alerts = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        total_incidents = c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

        recent_failures = [
            dict(r) for r in c.execute("""
                SELECT * FROM ingestion_telemetry
                WHERE status = 'FAILED'
                ORDER BY metric_id DESC LIMIT 10
            """).fetchall()
        ]

        class_counts = {}
        for r in c.execute("SELECT classification_type, COUNT(*) as cnt FROM alerts GROUP BY classification_type").fetchall():
            class_counts[r["classification_type"] or "known_attack"] = r["cnt"]

        method_counts = {}
        for r in c.execute("SELECT detection_method, COUNT(*) as cnt FROM alerts GROUP BY detection_method").fetchall():
            method_counts[r["detection_method"] or "rule"] = r["cnt"]

    return jsonify(
        status="operational",
        pipeline_status="Operational",
        last_successful_receipt=last_success["timestamp"] if last_success else None,
        last_event_time=last_success["timestamp"] if last_success else None,
        total_alerts_ingested=total_alerts,
        total_incidents=total_incidents,
        recent_failures=recent_failures,
        classification_counts=class_counts,
        classification_breakdown=class_counts,
        detection_method_breakdown=method_counts
    )

@app.get("/api/soc/security-events")
@auth("analyst")
def list_soc_security_events():
    """Retrieve SOC internal self-protection security logs with deduplicated event counts."""
    ev_type = request.args.get("event_type", "").upper().strip()
    limit = min(int(request.args.get("limit", 100)), 500)

    query = "SELECT * FROM soc_security_events WHERE 1=1"
    params = []
    if ev_type and ev_type != "ALL":
        query += " AND event_type = ?"
        params.append(ev_type)
    query += " ORDER BY event_id DESC LIMIT ?"
    params.append(limit)

    with db() as c:
        rows = c.execute(query, params).fetchall()
        events = []
        for r in rows:
            ed = dict(r)
            ed["client_ip"] = ed["source_ip"]
            ed["occurrences"] = ed["occurrence_count"]
            events.append(ed)
        summary = {}
        for r in c.execute("SELECT event_type, SUM(occurrence_count) as total FROM soc_security_events GROUP BY event_type").fetchall():
            summary[r["event_type"]] = r["total"]

    return jsonify(status="success", count=len(events), events=events, summary=summary)

@app.post("/api/soc/ml/evaluate")
@auth("analyst")
def evaluate_ml_payload():
    """Modular endpoint to test ML inference evaluation on candidate telemetry."""
    if not ml_engine:
        return jsonify(error="Machine Learning Engine is offline or uninstalled"), 503

    d = request.get_json(silent=True) or {}
    res = ml_engine.evaluate(d)
    if not res:
        return jsonify(error="Inference failed to evaluate features"), 400

    inf = res.to_dict()
    return jsonify(status="success", inference=inf, **inf)

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
