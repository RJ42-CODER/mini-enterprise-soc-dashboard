#!/usr/bin/env python3
"""Constrained nftables containment poller. Defaults to dry-run."""
import ipaddress, logging, os, subprocess, time
import requests

from pathlib import Path

def _load_env_file():
    env_path = Path(__file__).resolve().with_name(".env")
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return
    except ImportError:
        pass
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v

_load_env_file()

SOC_BASE_URL = os.getenv("SOC_BASE_URL", "http://127.0.0.1:8443").rstrip("/")
TOKEN = os.getenv("SOC_AGENT_TOKEN") or os.getenv("SOC_API_KEY") or ""
POLL_SECONDS = max(2, int(os.getenv("SOC_POLL_SECONDS", "3")))
DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"
VERIFY_TLS = os.getenv("SOC_VERIFY_TLS", "false").lower() == "true"
FAMILY, TABLE, SET = "inet", "mini_enterprise", "blocked_ips"
TIMEOUT = (3.05, 8)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def validate_ip(raw):
    ip = ipaddress.ip_address(raw)
    if not isinstance(ip, ipaddress.IPv4Address) or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ValueError("Expected a non-special IPv4 address")
    return str(ip)

def nft_file(statement):
    # statement contains only a validated IP and fixed command templates.
    return subprocess.run(["sudo", "/usr/sbin/nft", "-f", "-"], input=statement,
                          text=True, capture_output=True, timeout=10, check=False)

def is_blocked(ip):
    result = subprocess.run(["sudo", "/usr/sbin/nft", "list", "set", FAMILY, TABLE, SET],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not inspect nftables set")
    tokens = result.stdout.replace(",", " ").replace(";", " ").split()
    return ip in tokens

def block_ip(raw_ip, timeout_seconds=None):
    ip = validate_ip(raw_ip)
    if timeout_seconds is not None and not 1 <= int(timeout_seconds) <= 604800:
        raise ValueError("Timed block must be 1 second to 7 days")
    if DRY_RUN:
        logging.warning("[DRY RUN] Would block %s timeout=%s", ip, timeout_seconds)
        return True
    if is_blocked(ip):
        return True
    element = ip if timeout_seconds is None else f"{ip} timeout {int(timeout_seconds)}s"
    result = nft_file(f"add element {FAMILY} {TABLE} {SET} {{ {element} }}\\n")
    if result.returncode:
        logging.error("nft block failed: %s", result.stderr.strip())
        return False
    return is_blocked(ip)

def unblock_ip(raw_ip):
    ip = validate_ip(raw_ip)
    if DRY_RUN:
        logging.warning("[DRY RUN] Would unblock %s", ip)
        return True
    if not is_blocked(ip):
        return True
    result = nft_file(f"delete element {FAMILY} {TABLE} {SET} {{ {ip} }}\\n")
    if result.returncode:
        logging.error("nft unblock failed: %s", result.stderr.strip())
        return False
    return not is_blocked(ip)

def headers():
    if not TOKEN:
        raise RuntimeError("SOC_AGENT_TOKEN is not configured")
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

def report(action_id, status, message=""):
    r = requests.post(f"{SOC_BASE_URL}/api/agent/action-status", headers=headers(),
                      json={"action_id": action_id, "status": status, "message": message[:500]},
                      timeout=TIMEOUT, verify=VERIFY_TLS)
    r.raise_for_status()

def execute(action):
    action_id = int(action["action_id"])
    try:
        kind = action.get("type")
        if kind == "BLOCK_IP":
            ok = block_ip(action["target_ip"], action.get("timeout_seconds"))
        elif kind == "UNBLOCK_IP":
            ok = unblock_ip(action["target_ip"])
        else:
            raise ValueError("Unsupported action type")
        # DRY_RUN must never be presented as a real containment.
        status = "FAILED" if not ok else ("DRY_RUN" if DRY_RUN else "EXECUTED")
        report(action_id, status, "Dry-run only" if DRY_RUN else "")
    except Exception as exc:
        logging.exception("Action %s failed", action_id)
        try: report(action_id, "FAILED", str(exc))
        except Exception: logging.exception("Failed to report action status")

def main():
    if not TOKEN: raise SystemExit("Set SOC_AGENT_TOKEN")
    while True:
        try:
            r = requests.get(f"{SOC_BASE_URL}/api/agent/pending-actions", headers=headers(),
                             timeout=TIMEOUT, verify=VERIFY_TLS)
            r.raise_for_status()
            for action in r.json().get("actions", []): execute(action)
        except Exception: logging.exception("Polling failed")
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
