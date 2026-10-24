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
ENFORCEMENT_MODE = os.getenv("SOAR_ENFORCEMENT_MODE", "").lower().strip() in ("true", "1", "enabled", "enforce")
DRY_RUN = not ENFORCEMENT_MODE and (os.getenv("SOAR_DRY_RUN", "true").lower().strip() != "false")
VERIFY_TLS = os.getenv("SOC_VERIFY_TLS", "false").lower() == "true"
FAMILY, TABLE, SET = "inet", "mini_enterprise", "blocked_ips"
TIMEOUT = (3.05, 8)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def is_management_ip(raw_ip):
    try:
        ip = ipaddress.ip_address(raw_ip)
        if ip.is_loopback:
            return True
        from urllib.parse import urlsplit
        host = urlsplit(SOC_BASE_URL).hostname
        if host:
            try:
                if ip == ipaddress.ip_address(host):
                    return True
            except ValueError:
                pass
        prot = os.getenv("PROTECTED_IPS", "")
        if prot:
            for p in prot.split(","):
                p = p.strip()
                if p:
                    try:
                        if ip == ipaddress.ip_address(p) or ip in ipaddress.ip_network(p, strict=False):
                            return True
                    except ValueError:
                        pass
    except Exception:
        pass
    return False

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
    if is_management_ip(ip):
        raise ValueError(f"Cannot block target IP '{ip}': management connection is protected")
    if timeout_seconds is not None and not 1 <= int(timeout_seconds) <= 604800:
        raise ValueError("Timed block must be 1 second to 7 days")
    if DRY_RUN:
        logging.warning("[DRY RUN] Would block %s timeout=%s", ip, timeout_seconds)
        return True, f"[DRY_RUN] Simulated containment: would block {ip} (timeout={timeout_seconds}s)"
    if is_blocked(ip):
        return True, f"table inet {TABLE} {{ set {SET} {{ elements = {{ {ip} }} }} }}"
    element = ip if timeout_seconds is None else f"{ip} timeout {int(timeout_seconds)}s"
    result = nft_file(f"add element {FAMILY} {TABLE} {SET} {{ {element} }}\n")
    if result.returncode:
        err = result.stderr.strip() or "nft command execution failed"
        logging.error("nft block failed: %s", err)
        return False, err
    if not is_blocked(ip):
        return False, "Element was added but IP was not confirmed in nftables set"
    return True, f"table inet {TABLE} {{ set {SET} {{ elements = {{ {ip} }} }} }}"

def unblock_ip(raw_ip):
    ip = validate_ip(raw_ip)
    if DRY_RUN:
        logging.warning("[DRY RUN] Would unblock %s", ip)
        return True, f"[DRY_RUN] Simulated rollback: would unblock {ip}"
    if not is_blocked(ip):
        return True, f"IP {ip} not found in set {SET}"
    result = nft_file(f"delete element {FAMILY} {TABLE} {SET} {{ {ip} }}\n")
    if result.returncode:
        err = result.stderr.strip() or "nft command execution failed"
        logging.error("nft unblock failed: %s", err)
        return False, err
    if is_blocked(ip):
        return False, "Delete command succeeded but IP still confirmed in set"
    return True, f"IP {ip} removed from set {SET}"

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
    target_ip = action.get("target_ip")
    kind = action.get("type")

    try:
        if kind not in ("BLOCK_IP", "UNBLOCK_IP"):
            msg = f"Unsupported action type '{kind}': requires application instrumentation pending deployment"
            logging.warning("Action %s: %s", action_id, msg)
            report(action_id, "FAILED", msg)
            return

        if is_management_ip(target_ip):
            msg = f"Target IP {target_ip} is protected management connection; containment rejected"
            logging.error("Action %s: %s", action_id, msg)
            report(action_id, "FAILED", msg)
            return

        if DRY_RUN:
            logging.warning("[DRY RUN] Would execute %s on %s timeout=%s", kind, target_ip, action.get("timeout_seconds"))
            report(action_id, "DRY_RUN", f"[DRY_RUN] Simulated containment: would {kind} {target_ip}")
            return

        # Real enforcement mode: execute supported containment on host
        if kind == "BLOCK_IP":
            ok, evidence = block_ip(target_ip, action.get("timeout_seconds"))
        elif kind == "UNBLOCK_IP":
            ok, evidence = unblock_ip(target_ip)
        else:
            ok, evidence = False, "Unsupported action type"

        if not ok:
            logging.error("Real enforcement failed for action %s on %s: %s", action_id, target_ip, evidence)
            report(action_id, "FAILED", f"Real enforcement failed: {evidence}")
            return

        logging.info("Real enforcement executed for action %s on %s: %s", action_id, target_ip, evidence)
        report(action_id, "EXECUTED", f"Host nftables rule confirmed: {evidence}")

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
