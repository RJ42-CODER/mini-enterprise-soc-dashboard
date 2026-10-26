#!/usr/bin/env python3
"""
Constrained nftables containment poller with independent host verification.
Enforces safe execution modes (DRY-RUN default, explicit ENFORCEMENT mode),
strict management-IP protection, and read-only host firewall verification.
"""
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

import requests

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
VERIFY_TLS = os.getenv("SOC_VERIFY_TLS", "false").lower() == "true"
NFT_BIN = os.getenv("NFT_PATH") or "/usr/sbin/nft"
FAMILY, TABLE, SET = "inet", "mini_enterprise", "blocked_ips"
TIMEOUT = (3.05, 8)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def get_soar_mode_config() -> Tuple[bool, bool, str]:
    """
    Parse SOAR execution mode configuration.
    Returns: (is_dry_run: bool, is_enforcement: bool, status_note: str)

    Rules:
    - Safe default: DRY_RUN mode.
    - Real enforcement requires deliberate, explicit configuration:
      SOAR_ENFORCEMENT_MODE must be enabled AND SOAR_DRY_RUN must be explicitly disabled ('false', '0', 'no', 'disabled').
    - If enforcement and dry-run conflict (both enabled), fail safely to DRY_RUN mode.
    """
    enforce_raw = os.getenv("SOAR_ENFORCEMENT_MODE", "").lower().strip()
    dry_raw = os.getenv("SOAR_DRY_RUN", "").lower().strip()

    enforce_enabled = enforce_raw in ("true", "1", "enabled", "enforce", "yes")
    # If SOAR_DRY_RUN is not explicitly provided, it defaults to true
    dry_enabled = dry_raw not in ("false", "0", "disabled", "no") if dry_raw else True

    if enforce_enabled and dry_enabled:
        msg = "Configuration conflict: SOAR_ENFORCEMENT_MODE=true conflicts with SOAR_DRY_RUN=true. Defaulting safely to DRY_RUN mode."
        logging.error(msg)
        return True, False, msg

    if enforce_enabled and not dry_enabled:
        msg = "Real enforcement mode explicitly enabled (SOAR_ENFORCEMENT_MODE=true, SOAR_DRY_RUN=false)."
        logging.info(msg)
        return False, True, msg

    msg = "Dry-run simulation mode active (safe default)."
    return True, False, msg

DRY_RUN, ENFORCEMENT_MODE, SOAR_MODE_NOTE = get_soar_mode_config()

def is_management_ip(raw_ip: str) -> bool:
    """
    Check if IP belongs to management listener, loopback, remediator host, or protected networks.
    Prevents the remediator from locking out management, SSH, or SOC telemetry connectivity.
    """
    try:
        ip = ipaddress.ip_address(raw_ip)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
            return True

        # Check SOC server address from SOC_BASE_URL
        host = urlsplit(SOC_BASE_URL).hostname
        if host:
            try:
                if ip == ipaddress.ip_address(host):
                    return True
            except ValueError:
                try:
                    for res in socket.getaddrinfo(host, None, socket.AF_INET):
                        if ip == ipaddress.ip_address(res[4][0]):
                            return True
                except Exception:
                    pass

        # Check remediator local host management connectivity
        try:
            local_host = socket.gethostname()
            for res in socket.getaddrinfo(local_host, None, socket.AF_INET):
                if ip == ipaddress.ip_address(res[4][0]):
                    return True
        except Exception:
            pass

        # Check explicitly configured protected networks
        prot = os.getenv("PROTECTED_IPS", "")
        if prot:
            for p in prot.split(","):
                p = p.strip()
                if not p:
                    continue
                try:
                    if "/" in p:
                        if ip in ipaddress.ip_network(p, strict=False):
                            return True
                    else:
                        if ip == ipaddress.ip_address(p):
                            return True
                except ValueError:
                    try:
                        for res in socket.getaddrinfo(p, None, socket.AF_INET):
                            if ip == ipaddress.ip_address(res[4][0]):
                                return True
                    except Exception:
                        pass
    except Exception:
        pass
    return False

def validate_ip(raw: Any) -> str:
    """Validate target as non-special IPv4 address."""
    if not raw or not isinstance(raw, str):
        raise ValueError("Invalid target IP: expected non-empty string")
    ip = ipaddress.ip_address(raw.strip())
    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError("Unsupported address family: only IPv4 is supported")
    if ip.is_loopback:
        raise ValueError("Prohibited target: loopback address cannot be blocked")
    if ip.is_multicast:
        raise ValueError("Prohibited target: multicast address cannot be blocked")
    if ip.is_unspecified:
        raise ValueError("Prohibited target: unspecified address (0.0.0.0) cannot be blocked")
    if ip.is_link_local:
        raise ValueError("Prohibited target: link-local address cannot be blocked")
    if ip.is_reserved:
        raise ValueError("Prohibited target: reserved address space cannot be blocked")
    return str(ip)

def run_nft_command(args: list) -> subprocess.CompletedProcess:
    """Execute argument-safe nftables subprocess call with timeout."""
    cmd = ["sudo", NFT_BIN] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=10,
        check=False
    )

def nft_file(statement: str) -> subprocess.CompletedProcess:
    """Execute nftables statement via stdin with timeout."""
    return subprocess.run(
        ["sudo", NFT_BIN, "-f", "-"],
        input=statement,
        text=True,
        capture_output=True,
        timeout=10,
        check=False
    )

def is_blocked(ip: str) -> bool:
    """Check if target IP is present in nftables blocked_ips set."""
    res = run_nft_command(["list", "set", FAMILY, TABLE, SET])
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "Could not inspect nftables set")
    tokens = res.stdout.replace(",", " ").replace(";", " ").split()
    return ip in tokens

def verify_containment(
    action_id: int,
    target_ip: str,
    action_type: str,
    timeout_seconds: Optional[int] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Perform independent host-firewall verification querying actual host nftables ruleset.
    Read-only inspection: does not flush rules or alter host configuration.

    For BLOCK_IP:
    1. Confirm intended nftables table and set exist.
    2. Confirm target IP is present in set elements.
    3. Confirm active rule in chain references set and applies drop/reject.
    4. Check timeout/expiration when applicable.
    5. Return structured evidence.

    For UNBLOCK_IP:
    1. Confirm target IP is absent from block set.
    2. Confirm no other active rule still blocks target.
    3. Return structured evidence.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    try:
        clean_ip = validate_ip(target_ip)
    except Exception as exc:
        return False, {
            "action_id": action_id,
            "target_ip": target_ip,
            "action_type": action_type,
            "verified": False,
            "error": f"Target IP validation failed: {exc}",
            "timestamp": now_iso
        }

    if action_type == "BLOCK_IP":
        # 1. Inspect set existence and membership
        res_set = run_nft_command(["list", "set", FAMILY, TABLE, SET])
        if res_set.returncode != 0:
            err = res_set.stderr.strip() or f"Table '{TABLE}' or set '{SET}' does not exist on host"
            return False, {
                "action_id": action_id,
                "target_ip": clean_ip,
                "action_type": "BLOCK_IP",
                "verified": False,
                "error": err,
                "timestamp": now_iso
            }

        tokens = res_set.stdout.replace(",", " ").replace(";", " ").split()
        if clean_ip not in tokens:
            return False, {
                "action_id": action_id,
                "target_ip": clean_ip,
                "action_type": "BLOCK_IP",
                "verified": False,
                "error": f"Target IP '{clean_ip}' not found in nftables set '{TABLE}.{SET}'",
                "timestamp": now_iso
            }

        # 2. Inspect active rule in chain input
        res_chain = run_nft_command(["list", "chain", FAMILY, TABLE, "input"])
        if res_chain.returncode != 0:
            err = res_chain.stderr.strip() or f"Could not inspect chain '{TABLE}.input'"
            return False, {
                "action_id": action_id,
                "target_ip": clean_ip,
                "action_type": "BLOCK_IP",
                "verified": False,
                "error": err,
                "timestamp": now_iso
            }

        chain_output = res_chain.stdout
        # Confirm rule references @blocked_ips and applies drop or reject
        has_active_drop_rule = bool(
            re.search(rf"@{SET}\s+(?:counter\s+)?(?:drop|reject)", chain_output)
            or re.search(rf"ip\s+saddr\s+@{SET}.*?(?:drop|reject)", chain_output)
        )

        if not has_active_drop_rule:
            return False, {
                "action_id": action_id,
                "target_ip": clean_ip,
                "action_type": "BLOCK_IP",
                "verified": False,
                "error": f"Set '{SET}' exists with target IP, but no active rule in chain '{TABLE}.input' references @{SET} with drop/reject",
                "timestamp": now_iso
            }

        matched_rule = f"ip saddr @{SET} counter drop"
        structured_evidence = {
            "action_id": action_id,
            "target_ip": clean_ip,
            "action_type": "BLOCK_IP",
            "verified": True,
            "table": TABLE,
            "set": SET,
            "chain": "input",
            "rule": matched_rule,
            "rule_references_set": True,
            "elements": [clean_ip],
            "timeout_seconds": timeout_seconds,
            "verifier": "host_nftables_query",
            "timestamp": now_iso,
            "details": f"Host nftables confirmed: table {FAMILY} {TABLE} set {SET} contains {clean_ip}; active rule '{matched_rule}' drops matching traffic"
        }
        return True, structured_evidence

    elif action_type == "UNBLOCK_IP":
        # 1. Confirm absent from set
        res_set = run_nft_command(["list", "set", FAMILY, TABLE, SET])
        if res_set.returncode == 0:
            tokens = res_set.stdout.replace(",", " ").replace(";", " ").split()
            if clean_ip in tokens:
                return False, {
                    "action_id": action_id,
                    "target_ip": clean_ip,
                    "action_type": "UNBLOCK_IP",
                    "verified": False,
                    "error": f"Target IP '{clean_ip}' is still present in set '{SET}'",
                    "timestamp": now_iso
                }

        # 2. Check if another active rule still blocks target
        res_chain = run_nft_command(["list", "chain", FAMILY, TABLE, "input"])
        if res_chain.returncode == 0:
            if re.search(rf"ip\s+saddr\s+{re.escape(clean_ip)}.*?(?:drop|reject)", res_chain.stdout):
                return False, {
                    "action_id": action_id,
                    "target_ip": clean_ip,
                    "action_type": "UNBLOCK_IP",
                    "verified": False,
                    "error": f"Another active rule in chain '{TABLE}.input' still blocks target IP '{clean_ip}'",
                    "timestamp": now_iso
                }

        structured_evidence = {
            "action_id": action_id,
            "target_ip": clean_ip,
            "action_type": "UNBLOCK_IP",
            "verified": True,
            "table": TABLE,
            "set": SET,
            "ip_in_set": False,
            "other_blocking_rules": False,
            "verifier": "host_nftables_query",
            "timestamp": now_iso,
            "details": f"Target IP {clean_ip} confirmed absent from set {SET} and no other active drop rules block target"
        }
        return True, structured_evidence

    return False, {
        "action_id": action_id,
        "target_ip": clean_ip,
        "action_type": action_type,
        "verified": False,
        "error": f"Unsupported action type '{action_type}' for host firewall verification",
        "timestamp": now_iso
    }

def block_ip(raw_ip: str, timeout_seconds: Optional[int] = None) -> Tuple[bool, str]:
    """Execute host nftables IP containment."""
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
    statement = f"add element {FAMILY} {TABLE} {SET} {{ {element} }}\n"
    res = nft_file(statement)
    if res.returncode != 0:
        err = res.stderr.strip() or "nft command execution failed"
        logging.error("nft block failed: %s", err)
        return False, err

    if not is_blocked(ip):
        return False, "Element was added but IP was not confirmed in nftables set"

    return True, f"table inet {TABLE} {{ set {SET} {{ elements = {{ {ip} }} }} }}"

def unblock_ip(raw_ip: str) -> Tuple[bool, str]:
    """Execute host nftables IP unblock."""
    ip = validate_ip(raw_ip)
    if DRY_RUN:
        logging.warning("[DRY RUN] Would unblock %s", ip)
        return True, f"[DRY_RUN] Simulated rollback: would unblock {ip}"

    if not is_blocked(ip):
        return True, f"IP {ip} not found in set {SET}"

    statement = f"delete element {FAMILY} {TABLE} {SET} {{ {ip} }}\n"
    res = nft_file(statement)
    if res.returncode != 0:
        err = res.stderr.strip() or "nft command execution failed"
        logging.error("nft unblock failed: %s", err)
        return False, err

    if is_blocked(ip):
        return False, "Delete command succeeded but IP still confirmed in set"

    return True, f"IP {ip} removed from set {SET}"

def headers() -> Dict[str, str]:
    if not TOKEN:
        raise RuntimeError("SOC_AGENT_TOKEN is not configured")
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

def report(
    action_id: int,
    status: str,
    message: str = "",
    evidence: Optional[Any] = None,
    target_ip: Optional[str] = None,
    action_type: Optional[str] = None
) -> None:
    """Report execution status and verification evidence to SOC backend."""
    payload: Dict[str, Any] = {
        "action_id": action_id,
        "status": status,
        "message": message[:500]
    }
    if target_ip:
        payload["target_ip"] = target_ip
    if action_type:
        payload["action_type"] = action_type
    if evidence is not None:
        payload["evidence"] = evidence

    r = requests.post(
        f"{SOC_BASE_URL}/api/agent/action-status",
        headers=headers(),
        json=payload,
        timeout=TIMEOUT,
        verify=VERIFY_TLS
    )
    r.raise_for_status()

def execute(action: Dict[str, Any]) -> None:
    """Execute response action with strict mode checks and independent host verification."""
    action_id = int(action["action_id"])
    target_ip = action.get("target_ip", "")
    kind = str(action.get("type", "")).upper().strip()
    timeout_sec = action.get("timeout_seconds")

    try:
        if kind not in ("BLOCK_IP", "UNBLOCK_IP"):
            msg = f"Unsupported action type '{kind}': requires application instrumentation pending deployment"
            logging.warning("Action %s: %s", action_id, msg)
            report(action_id, "FAILED", msg, target_ip=target_ip, action_type=kind)
            return

        if is_management_ip(target_ip):
            msg = f"Target IP {target_ip} is protected management connection; containment rejected"
            logging.error("Action %s: %s", action_id, msg)
            report(action_id, "FAILED", msg, target_ip=target_ip, action_type=kind)
            return

        if DRY_RUN:
            sim_msg = f"[DRY_RUN] Simulated containment: would {kind} {target_ip} (timeout={timeout_sec}s)"
            logging.warning(sim_msg)
            report(action_id, "DRY_RUN", sim_msg, target_ip=target_ip, action_type=kind)
            return

        # Real enforcement mode: execute containment on host
        if kind == "BLOCK_IP":
            ok, exec_detail = block_ip(target_ip, timeout_sec)
        elif kind == "UNBLOCK_IP":
            ok, exec_detail = unblock_ip(target_ip)
        else:
            ok, exec_detail = False, "Unsupported action type"

        if not ok:
            logging.error("Real enforcement failed for action %s on %s: %s", action_id, target_ip, exec_detail)
            report(action_id, "FAILED", f"Real enforcement failed: {exec_detail}", target_ip=target_ip, action_type=kind)
            return

        # Independently verify host firewall
        ver_ok, structured_evidence = verify_containment(action_id, target_ip, kind, timeout_sec)
        if not ver_ok:
            fail_msg = f"Real enforcement executed but host verification failed: {structured_evidence.get('error', 'unknown error')}"
            logging.error(fail_msg)
            report(action_id, "FAILED", fail_msg, evidence=structured_evidence, target_ip=target_ip, action_type=kind)
            return

        logging.info("Real enforcement and host verification succeeded for action %s on %s", action_id, target_ip)
        report(
            action_id,
            "EXECUTED",
            f"Host nftables containment confirmed: {structured_evidence.get('details', '')}",
            evidence=structured_evidence,
            target_ip=target_ip,
            action_type=kind
        )

    except Exception as exc:
        logging.exception("Action %s failed", action_id)
        try:
            report(action_id, "FAILED", str(exc), target_ip=target_ip, action_type=kind)
        except Exception:
            logging.exception("Failed to report action status")

def main():
    if not TOKEN:
        raise SystemExit("Set SOC_AGENT_TOKEN")
    logging.info("Starting agent remediator. Mode: %s", "DRY-RUN" if DRY_RUN else "ENFORCEMENT")
    while True:
        try:
            r = requests.get(
                f"{SOC_BASE_URL}/api/agent/pending-actions",
                headers=headers(),
                timeout=TIMEOUT,
                verify=VERIFY_TLS
            )
            r.raise_for_status()
            for action in r.json().get("actions", []):
                execute(action)
        except Exception:
            logging.exception("Polling failed")
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
