"""
Comprehensive Focused Test Suite for Mini Enterprise Defensive SOC Dashboard.
Covers all 10 required verification categories using an isolated temporary database.
Does NOT modify or delete live database files.
"""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

# Import backend application and helpers
import soc_backend
from soc_backend import (
    app, init_db, db, get_agent_token, get_analyst_token, REGISTRY,
    validate_startup_config, get_bind_host, get_port,
    reset_dir_fuzz_tracker, get_dir_fuzz_threshold, get_dir_fuzz_window,
    get_dir_fuzz_max_sources, probe_tracker
)

TEST_AGENT_TOKEN = "test_agent_secret_token_12345"
TEST_ANALYST_TOKEN = "test_analyst_secret_token_67890"

class TestDefensiveSocBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create an isolated temporary SQLite database for testing
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = str(Path(cls.temp_dir.name) / "test_soc_telemetry.db")

        # Configure Flask app to use test database and test credentials
        app.config["TESTING"] = True
        app.config["SOC_DB_PATH"] = cls.test_db_path
        app.config["SOC_AGENT_TOKEN"] = TEST_AGENT_TOKEN
        app.config["ANALYST_TOKEN"] = TEST_ANALYST_TOKEN

        # Initialize schema in temporary database
        init_db(cls.test_db_path)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        import gc
        gc.collect()
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def setUp(self):
        # Snapshot environment variables and Flask app.config for strict test isolation
        self._orig_env = dict(os.environ)
        self._orig_config = dict(app.config)

        # Clear rows in temporary test database between tests
        with db(self.test_db_path) as c:
            c.execute("DELETE FROM incident_notes")
            c.execute("DELETE FROM alerts")
            c.execute("DELETE FROM response_actions")
            c.execute("DELETE FROM incidents")
        reset_dir_fuzz_tracker()

    def tearDown(self):
        # Restore environment variables even if assertions failed
        os.environ.clear()
        os.environ.update(self._orig_env)

        # Restore Flask app config even if assertions failed
        app.config.clear()
        app.config.update(self._orig_config)

        # Clean up database state and in-memory tracker
        try:
            with db(self.test_db_path) as c:
                c.execute("DELETE FROM incident_notes")
                c.execute("DELETE FROM alerts")
                c.execute("DELETE FROM response_actions")
                c.execute("DELETE FROM incidents")
        except Exception:
            pass
        reset_dir_fuzz_tracker()

    # -------------------------------------------------------------------------
    # 1. Missing Required Configuration
    # -------------------------------------------------------------------------
    def test_01_missing_configuration_returns_503(self):
        """Protected endpoints return HTTP 503 if secrets are not configured."""
        orig_agent = app.config.get("SOC_AGENT_TOKEN")
        orig_analyst = app.config.get("ANALYST_TOKEN")
        try:
            app.config["SOC_AGENT_TOKEN"] = ""
            app.config["ANALYST_TOKEN"] = ""
            
            # Temporarily clear env vars if set
            saved_env_agent = os.environ.pop("SOC_AGENT_TOKEN", None)
            saved_env_key = os.environ.pop("SOC_API_KEY", None)
            saved_env_analyst = os.environ.pop("ANALYST_TOKEN", None)

            # Ingest should return 503
            r_ingest = self.client.post("/api/events", json={"source_ip": "10.0.0.5", "signature": "SQL_INJECTION"})
            self.assertEqual(r_ingest.status_code, 503)
            self.assertIn("auth not configured", r_ingest.get_json()["error"])

            # Matrix should return 503
            r_matrix = self.client.get("/api/soc/mitre-matrix")
            self.assertEqual(r_matrix.status_code, 503)
            self.assertIn("auth not configured", r_matrix.get_json()["error"])

            # Restore env vars
            if saved_env_agent: os.environ["SOC_AGENT_TOKEN"] = saved_env_agent
            if saved_env_key: os.environ["SOC_API_KEY"] = saved_env_key
            if saved_env_analyst: os.environ["ANALYST_TOKEN"] = saved_env_analyst
        finally:
            app.config["SOC_AGENT_TOKEN"] = orig_agent
            app.config["ANALYST_TOKEN"] = orig_analyst

    # -------------------------------------------------------------------------
    # 2. Separate Agent and Analyst Authentication
    # -------------------------------------------------------------------------
    def test_02_separate_agent_and_analyst_tokens(self):
        """Agent token cannot access analyst routes; analyst token cannot access agent routes."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        # Analyst token rejected on agent ingestion endpoint
        r1 = self.client.post("/api/events", headers=analyst_headers, json={
            "source_ip": "10.0.0.1", "signature": "PORT_SCAN"
        })
        self.assertEqual(r1.status_code, 401)

        # Agent token rejected on analyst matrix endpoint
        r2 = self.client.get("/api/soc/mitre-matrix", headers=agent_headers)
        self.assertEqual(r2.status_code, 401)

        # Agent token rejected on analyst mitigation endpoint
        r3 = self.client.post("/api/soc/mitigate/block", headers=agent_headers, json={"target_ip": "10.0.0.1"})
        self.assertEqual(r3.status_code, 401)

    # -------------------------------------------------------------------------
    # 3. Valid Ingestion and Invalid Credentials
    # -------------------------------------------------------------------------
    def test_03_valid_ingestion_and_invalid_credentials(self):
        """Test valid Bearer token vs missing, wrong, or malformed credentials."""
        valid_payload = {"source_ip": "192.168.1.50", "signature": "SQL_INJECTION", "severity": "high"}

        # Missing header -> 401
        r_none = self.client.post("/api/events", json=valid_payload)
        self.assertEqual(r_none.status_code, 401)

        # Wrong token -> 401
        r_wrong = self.client.post("/api/events", headers={"Authorization": "Bearer wrong_token_xyz"}, json=valid_payload)
        self.assertEqual(r_wrong.status_code, 401)

        # Malformed header (missing Bearer prefix) -> 401
        r_malformed = self.client.post("/api/events", headers={"Authorization": f"Basic {TEST_AGENT_TOKEN}"}, json=valid_payload)
        self.assertEqual(r_malformed.status_code, 401)

        # Valid Bearer token -> 202
        r_ok = self.client.post("/api/events", headers={"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}, json=valid_payload)
        self.assertEqual(r_ok.status_code, 202)
        self.assertEqual(r_ok.get_json()["status"], "accepted")

    # -------------------------------------------------------------------------
    # 4. Invalid Source IPs and Unsupported Signatures
    # -------------------------------------------------------------------------
    def test_04_invalid_source_ips_and_unsupported_signatures(self):
        """Validate rejection of loopback, multicast, IPv6, invalid IPs and unknown signatures."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        # Loopback IPv4 (127.0.0.1) -> 400
        r_loop = self.client.post("/api/events", headers=headers, json={"source_ip": "127.0.0.1", "signature": "PORT_SCAN"})
        self.assertEqual(r_loop.status_code, 400)
        self.assertIn("non-special IPv4", r_loop.get_json()["error"])

        # Loopback subnet (127.0.1.1) -> 400
        r_loop2 = self.client.post("/api/events", headers=headers, json={"source_ip": "127.0.1.1", "signature": "PORT_SCAN"})
        self.assertEqual(r_loop2.status_code, 400)
        self.assertIn("non-special IPv4", r_loop2.get_json()["error"])

        # Unspecified IPv4 (0.0.0.0) -> 400
        r_unspec = self.client.post("/api/events", headers=headers, json={"source_ip": "0.0.0.0", "signature": "PORT_SCAN"})
        self.assertEqual(r_unspec.status_code, 400)
        self.assertIn("non-special IPv4", r_unspec.get_json()["error"])

        # IPv6 address -> 400
        r_v6 = self.client.post("/api/events", headers=headers, json={"source_ip": "::1", "signature": "PORT_SCAN"})
        self.assertEqual(r_v6.status_code, 400)

        # Multicast IP (224.0.0.1) -> 400
        r_multi = self.client.post("/api/events", headers=headers, json={"source_ip": "224.0.0.1", "signature": "PORT_SCAN"})
        self.assertEqual(r_multi.status_code, 400)

        # Non-IP string -> 400
        r_invalid = self.client.post("/api/events", headers=headers, json={"source_ip": "attacker-box", "signature": "PORT_SCAN"})
        self.assertEqual(r_invalid.status_code, 400)

        # Missing source_ip -> 400
        r_missing = self.client.post("/api/events", headers=headers, json={"signature": "PORT_SCAN"})
        self.assertEqual(r_missing.status_code, 400)

        # Unsupported signature -> 400
        r_unsup = self.client.post("/api/events", headers=headers, json={"source_ip": "10.0.0.99", "signature": "UNKNOWN_ATTACK"})
        self.assertEqual(r_unsup.status_code, 400)
        self.assertIn("Unsupported signature", r_unsup.get_json()["error"])

        # Non-attack normal connection not treated as port scan -> 400
        r_conn = self.client.post("/api/events", headers=headers, json={"source_ip": "10.0.0.99", "signature": "CONNECTION"})
        self.assertEqual(r_conn.status_code, 400)

        # Canonical normalization: website event types map cleanly
        for alias, expected_sig in [
            ("sqli", "SQL_INJECTION"),
            ("directory_traversal", "PATH_TRAVERSAL"),
            ("portscan", "PORT_SCAN"),
            ("brute_force", "BRUTE_FORCE_AUTH"),
            ("cmd_injection", "COMMAND_INJECTION"),
            ("dir_fuzzing", "DIR_FUZZ"),
        ]:
            r_norm = self.client.post("/api/events", headers=headers, json={"source_ip": "10.0.0.88", "event_type": alias})
            self.assertEqual(r_norm.status_code, 202, f"Failed for alias {alias}")
            self.assertEqual(r_norm.get_json()["signature"], expected_sig)

        # Heartbeat event acknowledged without creating an attack alert
        r_hb = self.client.post("/api/events", headers=headers, json={"source_ip": "10.0.0.1", "event_type": "HEARTBEAT"})
        self.assertEqual(r_hb.status_code, 202)
        self.assertEqual(r_hb.get_json()["event_type"], "heartbeat")

        # Confirm no alerts were stored for the heartbeat
        with db(self.test_db_path) as c:
            hb_count = c.execute("SELECT COUNT(*) FROM alerts WHERE signature='HEARTBEAT'").fetchone()[0]
            self.assertEqual(hb_count, 0)

    # -------------------------------------------------------------------------
    # 5. HTTP 202 Response Behavior
    # -------------------------------------------------------------------------
    def test_05_http_202_response_semantics(self):
        """Successful ingestion returns 202 with status, event_id, mitre_id, and signature."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        payload = {
            "source_ip": "192.168.10.15",
            "signature": "COMMAND_INJECTION",
            "severity": "critical",
            "message": "whoami attempted via web parameter"
        }
        res = self.client.post("/api/events", headers=headers, json=payload)
        self.assertEqual(res.status_code, 202)
        data = res.get_json()
        self.assertEqual(data["status"], "accepted")
        self.assertTrue(len(data["event_id"]) > 0)
        self.assertEqual(data["mitre_id"], "T1059")
        self.assertEqual(data["signature"], "COMMAND_INJECTION")

    # -------------------------------------------------------------------------
    # 6. Persistent Database Insertion and Duplicate Event IDs
    # -------------------------------------------------------------------------
    def test_06_persistent_db_insertion_and_idempotent_deduplication(self):
        """Events are persisted to SQLite; duplicate event_id is safely idempotent."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        fixed_event_id = "evt-unique-test-uuid-9999"
        payload = {
            "event_id": fixed_event_id,
            "source_ip": "10.10.10.100",
            "signature": "SQL_INJECTION",
            "severity": "high",
            "message": "' OR 1=1 in login field"
        }

        # First submission
        res1 = self.client.post("/api/events", headers=headers, json=payload)
        self.assertEqual(res1.status_code, 202)

        # Verify persistent row in SQLite
        with db(self.test_db_path) as c:
            row = c.execute("SELECT * FROM alerts WHERE event_id=?", (fixed_event_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["source_ip"], "10.10.10.100")
            self.assertEqual(row["signature"], "SQL_INJECTION")
            self.assertEqual(row["severity"], "high")
            self.assertEqual(row["mitre_id"], "T1190")

        # Second submission with exact same event_id
        res2 = self.client.post("/api/events", headers=headers, json=payload)
        self.assertEqual(res2.status_code, 202)

        # Verify no duplicate row was created (count remains 1)
        with db(self.test_db_path) as c:
            count = c.execute("SELECT COUNT(*) FROM alerts WHERE event_id=?", (fixed_event_id,)).fetchone()[0]
            self.assertEqual(count, 1)

    # -------------------------------------------------------------------------
    # 7. Invalid JSON and Malformed Payloads
    # -------------------------------------------------------------------------
    def test_07_invalid_json_and_malformed_payloads(self):
        """Test rejection of non-JSON bodies, lists, and invalid severity values."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        # Non-JSON content-type
        r_raw = self.client.post("/api/events", headers=headers, data="not json", content_type="text/plain")
        self.assertEqual(r_raw.status_code, 400)

        # JSON array instead of dictionary
        r_list = self.client.post("/api/events", headers=headers, json=[{"source_ip": "10.0.0.1"}])
        self.assertEqual(r_list.status_code, 400)

        # Invalid severity string
        r_sev = self.client.post("/api/events", headers=headers, json={
            "source_ip": "10.0.0.1", "signature": "PORT_SCAN", "severity": "ultra_fatal"
        })
        self.assertEqual(r_sev.status_code, 400)
        self.assertIn("Invalid 'severity'", r_sev.get_json()["error"])

    # -------------------------------------------------------------------------
    # 8. Dashboard Authentication and MITRE Matrix Polling
    # -------------------------------------------------------------------------
    def test_08_dashboard_auth_and_matrix_polling(self):
        """Index page loads unauthenticated; matrix endpoint requires analyst token."""
        # Index loads with 200 without auth
        r_index = self.client.get("/")
        self.assertEqual(r_index.status_code, 200)
        self.assertIn(b"MINI ENTERPRISE DEFENSIVE SOC", r_index.data)

        # Matrix endpoint requires analyst token
        r_unauth = self.client.get("/api/soc/mitre-matrix")
        self.assertEqual(r_unauth.status_code, 401)

        # Ingest an alert
        self.client.post("/api/events", headers={"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}, json={
            "source_ip": "10.20.30.40", "signature": "DIR_FUZZ", "severity": "medium"
        })

        # Matrix query with valid analyst token
        r_auth = self.client.get("/api/soc/mitre-matrix", headers={"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"})
        self.assertEqual(r_auth.status_code, 200)
        data = r_auth.get_json()
        self.assertEqual(data["detected_techniques"], 1)
        self.assertEqual(data["mitigated_techniques"], 0)

        # Locate DIR_FUZZ technique card
        dir_fuzz_card = next(c for c in data["matrix"] if c["signature"] == "DIR_FUZZ")
        self.assertEqual(dir_fuzz_card["alert_count"], 1)
        self.assertEqual(dir_fuzz_card["state"], "DETECTED")

    # -------------------------------------------------------------------------
    # 9. Startup with Configured Non-Default Bind Address and Port
    # -------------------------------------------------------------------------
    def test_09_bind_address_and_port_environment_parsing(self):
        """Verify get_bind_host() and get_port() helpers parse environment and app.config correctly."""
        # 1. Environment variable parsing
        os.environ["SOC_BIND_HOST"] = "192.168.31.73"
        os.environ["SOC_PORT"] = "9090"
        self.assertEqual(get_bind_host(), "192.168.31.73")
        self.assertEqual(get_port(), 9090)

        # 2. Flask app.config precedence over environment variables
        app.config["SOC_BIND_HOST"] = "10.0.0.50"
        app.config["SOC_PORT"] = "8080"
        self.assertEqual(get_bind_host(), "10.0.0.50")
        self.assertEqual(get_port(), 8080)

        # 3. Fallback defaults when values are missing
        app.config.pop("SOC_BIND_HOST", None)
        app.config.pop("SOC_PORT", None)
        os.environ.pop("SOC_BIND_HOST", None)
        os.environ.pop("SOC_PORT", None)
        self.assertEqual(get_bind_host(), "0.0.0.0")
        self.assertEqual(get_port(), 8443)

        # 4. Fallback on invalid port values (non-numeric and out-of-range)
        app.config["SOC_PORT"] = "invalid_port"
        self.assertEqual(get_port(), 8443)
        app.config["SOC_PORT"] = "99999"
        self.assertEqual(get_port(), 8443)

    # -------------------------------------------------------------------------
    # 10. Controlled Integration Test (Full Lifecycle)
    # -------------------------------------------------------------------------
    def test_10_controlled_integration_lifecycle(self):
        """
        Complete end-to-end lifecycle in isolated test database:
        1. Ingest alert -> DETECTED in matrix
        2. Analyst queues block -> PENDING action
        3. Agent checks pending -> empty (not approved)
        4. Analyst approves action -> APPROVED
        5. Agent polls action -> finds action
        6. Agent reports status -> EXECUTED
        7. Analyst verifies containment -> VERIFIED
        8. Matrix reflects MITIGATED and resilience index = 100%
        """
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "192.168.50.77"

        # Step 1: Ingest SQL_INJECTION alert
        r_ingest = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_ip, "signature": "SQL_INJECTION", "severity": "high"
        })
        self.assertEqual(r_ingest.status_code, 202)

        # Verify initial matrix state: DETECTED, 0 mitigated
        r_m1 = self.client.get("/api/soc/mitre-matrix", headers=analyst_headers)
        self.assertEqual(r_m1.get_json()["detected_techniques"], 1)
        self.assertEqual(r_m1.get_json()["mitigated_techniques"], 0)
        self.assertEqual(r_m1.get_json()["resilience_index"], 0.0)

        # Step 2: Analyst queues containment block
        r_block = self.client.post("/api/soc/mitigate/block", headers=analyst_headers, json={
            "target_ip": target_ip, "timeout_seconds": 3600
        })
        self.assertEqual(r_block.status_code, 202)
        action_id = r_block.get_json()["action_id"]

        # Step 3: Agent checks pending actions (must be empty because it is still PENDING approval)
        r_agent_pending1 = self.client.get("/api/agent/pending-actions", headers=agent_headers)
        self.assertEqual(len(r_agent_pending1.get_json()["actions"]), 0)

        # Step 4: Analyst approves the action
        r_app = self.client.post(f"/api/soc/response-actions/{action_id}/approve", headers=analyst_headers)
        self.assertEqual(r_app.status_code, 200)
        self.assertEqual(r_app.get_json()["status"], "APPROVED")

        # Step 5: Agent polls pending actions (now finds approved action)
        r_agent_pending2 = self.client.get("/api/agent/pending-actions", headers=agent_headers)
        actions = r_agent_pending2.get_json()["actions"]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action_id"], action_id)
        self.assertEqual(actions[0]["target_ip"], target_ip)

        # Step 6: Agent reports execution status
        r_status = self.client.post("/api/agent/action-status", headers=agent_headers, json={
            "action_id": action_id, "status": "EXECUTED", "message": "nftables element added"
        })
        self.assertEqual(r_status.status_code, 200)

        # Matrix should STILL be DETECTED (because EXECUTED is not VERIFIED)
        r_m2 = self.client.get("/api/soc/mitre-matrix", headers=analyst_headers)
        self.assertEqual(r_m2.get_json()["mitigated_techniques"], 0)

        # Step 7: Analyst verifies containment
        r_verify = self.client.post(f"/api/soc/response-actions/{action_id}/verify", headers=analyst_headers)
        self.assertEqual(r_verify.status_code, 200)
        self.assertEqual(r_verify.get_json()["status"], "VERIFIED")

        # Step 8: Matrix reflects MITIGATED and resilience index = 100%
        r_m3 = self.client.get("/api/soc/mitre-matrix", headers=analyst_headers)
        data3 = r_m3.get_json()
        self.assertEqual(data3["detected_techniques"], 1)
        self.assertEqual(data3["mitigated_techniques"], 1)
        self.assertEqual(data3["resilience_index"], 100.0)

        card = next(c for c in data3["matrix"] if c["signature"] == "SQL_INJECTION")
        self.assertEqual(card["state"], "MITIGATED")
        self.assertEqual(card["mitigated_count"], 1)

    # -------------------------------------------------------------------------
    # 11. Incident Creation and Alert Correlation
    # -------------------------------------------------------------------------
    def test_11_incident_creation_and_alert_correlation(self):
        """Events are correlated into incidents; severity escalates; filtering works."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        # 1. Ingest first alert
        r1 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "10.0.0.15", "signature": "PORT_SCAN", "severity": "low"
        })
        self.assertEqual(r1.status_code, 202)
        inc_id1 = r1.get_json().get("incident_id")
        self.assertIsNotNone(inc_id1)

        # Verify incident created with status 'NEW'
        with db(self.test_db_path) as c:
            row = c.execute("SELECT * FROM incidents WHERE incident_id=?", (inc_id1,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "NEW")
            self.assertEqual(row["source_ip"], "10.0.0.15")
            self.assertEqual(row["signature"], "PORT_SCAN")
            self.assertEqual(row["severity"], "low")

        # 2. Ingest second alert with same IP and signature, but higher severity
        r2 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "10.0.0.15", "signature": "PORT_SCAN", "severity": "high"
        })
        self.assertEqual(r2.status_code, 202)
        inc_id2 = r2.get_json().get("incident_id")
        self.assertEqual(inc_id1, inc_id2, "Second alert should correlate to existing open incident")

        # Verify severity escalated to 'high'
        with db(self.test_db_path) as c:
            row = c.execute("SELECT * FROM incidents WHERE incident_id=?", (inc_id1,)).fetchone()
            self.assertEqual(row["severity"], "high")

        # 3. Ingest third alert with different IP -> creates distinct incident
        r3 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "10.0.0.20", "signature": "BRUTE_FORCE_AUTH", "severity": "medium"
        })
        self.assertEqual(r3.status_code, 202)
        inc_id3 = r3.get_json().get("incident_id")
        self.assertNotEqual(inc_id1, inc_id3)

        # 4. Query /api/soc/incidents
        # Unauthenticated query -> 401
        self.assertEqual(self.client.get("/api/soc/incidents").status_code, 401)

        # Authenticated query -> list of 2 incidents
        r_list = self.client.get("/api/soc/incidents", headers=analyst_headers)
        self.assertEqual(r_list.status_code, 200)
        items = r_list.get_json()["incidents"]
        self.assertEqual(len(items), 2)

        # Filtering by status=NEW
        r_new = self.client.get("/api/soc/incidents?status=NEW", headers=analyst_headers)
        self.assertEqual(len(r_new.get_json()["incidents"]), 2)

        # Filtering by source_ip
        r_ip = self.client.get("/api/soc/incidents?source_ip=10.0.0.15", headers=analyst_headers)
        self.assertEqual(len(r_ip.get_json()["incidents"]), 1)
        self.assertEqual(r_ip.get_json()["incidents"][0]["id"], inc_id1)
        self.assertEqual(r_ip.get_json()["incidents"][0]["alert_count"], 2)

    # -------------------------------------------------------------------------
    # 12. Incident Details Dossier
    # -------------------------------------------------------------------------
    def test_12_incident_details_dossier(self):
        """Incident details endpoint provides complete evidence, MITRE info, and timeline."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        # Ingest alert to create incident
        r_ingest = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "192.168.1.99", "signature": "PATH_TRAVERSAL", "severity": "high",
            "message": "Attempted traversal to /etc/passwd"
        })
        inc_id = r_ingest.get_json()["incident_id"]

        # Detail query
        r_detail = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_headers)
        self.assertEqual(r_detail.status_code, 200)
        data = r_detail.get_json()["incident"]

        self.assertEqual(data["id"], inc_id)
        self.assertEqual(data["source_ip"], "192.168.1.99")
        self.assertEqual(data["signature"], "PATH_TRAVERSAL")
        self.assertEqual(data["technique_id"], "T1083")
        self.assertEqual(data["technique_name"], "File and Directory Discovery")
        self.assertEqual(data["status"], "NEW")
        self.assertIsNone(data["classification"])
        self.assertEqual(len(data["correlated_alerts"]), 1)
        self.assertTrue(len(data["timeline"]) >= 1)

        # Non-existent incident -> 404
        r_404 = self.client.get("/api/soc/incidents/999999", headers=analyst_headers)
        self.assertEqual(r_404.status_code, 404)

    # -------------------------------------------------------------------------
    # 13. Workflow Status Transitions and Closure
    # -------------------------------------------------------------------------
    def test_13_workflow_status_transitions_and_closure(self):
        """Validate 8-stage workflow transitions and mandatory closure rationale."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        # Ingest alert
        r = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "172.16.0.44", "signature": "COMMAND_INJECTION", "severity": "critical"
        })
        inc_id = r.get_json()["incident_id"]

        # 1. Transition to TRIAGE
        r_triage = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_headers, json={
            "status": "TRIAGE"
        })
        self.assertEqual(r_triage.status_code, 200)
        self.assertEqual(r_triage.get_json()["incident"]["status"], "TRIAGE")

        # 2. Transition to INVESTIGATING
        r_inv = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_headers, json={
            "status": "INVESTIGATING"
        })
        self.assertEqual(r_inv.status_code, 200)
        self.assertEqual(r_inv.get_json()["incident"]["status"], "INVESTIGATING")

        # 3. Invalid status -> 400
        r_invalid = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_headers, json={
            "status": "UNKNOWN_STAGE"
        })
        self.assertEqual(r_invalid.status_code, 400)
        self.assertIn("Invalid status", r_invalid.get_json()["error"])

        # 4. Transition to CLOSED without rationale -> 400
        r_no_rat = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_headers, json={
            "status": "CLOSED"
        })
        self.assertEqual(r_no_rat.status_code, 400)
        self.assertIn("rationale is required", r_no_rat.get_json()["error"])

        # 5. Transition to CLOSED with valid rationale -> 200
        r_closed = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_headers, json={
            "status": "CLOSED",
            "rationale": "Authorized scheduled penetration test by internal security team."
        })
        self.assertEqual(r_closed.status_code, 200)
        self.assertEqual(r_closed.get_json()["incident"]["status"], "CLOSED")

        # Verify closure details in DB
        with db(self.test_db_path) as c:
            row = c.execute("SELECT * FROM incidents WHERE incident_id=?", (inc_id,)).fetchone()
            self.assertEqual(row["status"], "CLOSED")
            self.assertIsNotNone(row["closed_at"])
            self.assertIn("Authorized scheduled penetration test", row["closure_rationale"])

    # -------------------------------------------------------------------------
    # 14. Incident Classification
    # -------------------------------------------------------------------------
    def test_14_incident_classification(self):
        """Analyst can classify an incident with mandatory rationale."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        r = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "10.50.0.22", "signature": "SQL_INJECTION", "severity": "high"
        })
        inc_id = r.get_json()["incident_id"]

        # Missing rationale -> 400
        r_no_rat = self.client.post(f"/api/soc/incidents/{inc_id}/classify", headers=analyst_headers, json={
            "classification": "CONFIRMED_MALICIOUS"
        })
        self.assertEqual(r_no_rat.status_code, 400)
        self.assertIn("rationale", r_no_rat.get_json()["error"].lower())

        # Invalid classification -> 400
        r_bad_class = self.client.post(f"/api/soc/incidents/{inc_id}/classify", headers=analyst_headers, json={
            "classification": "FALSE_ALARM_RANDOM", "rationale": "Looks fine"
        })
        self.assertEqual(r_bad_class.status_code, 400)
        self.assertIn("Invalid classification", r_bad_class.get_json()["error"])

        # Valid classification: CONFIRMED_MALICIOUS
        r_valid = self.client.post(f"/api/soc/incidents/{inc_id}/classify", headers=analyst_headers, json={
            "classification": "CONFIRMED_MALICIOUS",
            "rationale": "Payload contains union select syntax targeted at auth table."
        })
        self.assertEqual(r_valid.status_code, 200)
        data = r_valid.get_json()["incident"]
        self.assertEqual(data["classification"], "CONFIRMED_MALICIOUS")
        self.assertEqual(data["status"], "CLASSIFIED")

    # -------------------------------------------------------------------------
    # 15. Analyst Notes and Audit Trail
    # -------------------------------------------------------------------------
    def test_15_analyst_notes_and_audit_trail(self):
        """Analysts can append timestamped investigation notes to an incident."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        r = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "10.60.0.88", "signature": "DIR_FUZZ", "severity": "medium"
        })
        inc_id = r.get_json()["incident_id"]

        # Empty note -> 400
        r_empty = self.client.post(f"/api/soc/incidents/{inc_id}/notes", headers=analyst_headers, json={
            "note": "   "
        })
        self.assertEqual(r_empty.status_code, 400)

        # Add analyst note
        r_add = self.client.post(f"/api/soc/incidents/{inc_id}/notes", headers=analyst_headers, json={
            "note": "Investigated web server access logs; found 240 requests to admin paths in 60s."
        })
        self.assertEqual(r_add.status_code, 201)

        # Verify note in incident details
        r_detail = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_headers)
        notes = r_detail.get_json()["incident"]["notes"]
        self.assertTrue(any("240 requests" in n["note"] for n in notes))

    # -------------------------------------------------------------------------
    # 16. Containment Integration with Incident Workflow
    # -------------------------------------------------------------------------
    def test_16_containment_integration_with_incident_workflow(self):
        """Containment actions update incident status to CONTAINMENT_PENDING_APPROVAL and CONTAINED."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "192.168.100.55"

        # 1. Ingest alert -> Incident created
        r_ingest = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_ip, "signature": "COMMAND_INJECTION", "severity": "critical"
        })
        inc_id = r_ingest.get_json()["incident_id"]

        # 2. Analyst queues block containment with incident_id
        r_block = self.client.post("/api/soc/mitigate/block", headers=analyst_headers, json={
            "target_ip": target_ip, "incident_id": inc_id, "timeout_seconds": 1800
        })
        self.assertEqual(r_block.status_code, 202)
        action_id = r_block.get_json()["action_id"]

        # Verify incident transitioned to CONTAINMENT_PENDING_APPROVAL
        r_inc1 = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_headers)
        self.assertEqual(r_inc1.get_json()["incident"]["status"], "CONTAINMENT_PENDING_APPROVAL")

        # Matrix should STILL be DETECTED, not MITIGATED
        r_mat1 = self.client.get("/api/soc/mitre-matrix", headers=analyst_headers)
        self.assertEqual(r_mat1.get_json()["mitigated_techniques"], 0)

        # 3. Analyst approves response action
        r_app = self.client.post(f"/api/soc/response-actions/{action_id}/approve", headers=analyst_headers)
        self.assertEqual(r_app.status_code, 200)

        # 4. Agent reports execution
        r_exec = self.client.post("/api/agent/action-status", headers=agent_headers, json={
            "action_id": action_id, "status": "EXECUTED", "message": "Firewall rule created"
        })
        self.assertEqual(r_exec.status_code, 200)

        # Matrix should STILL be DETECTED (executed is not verified)
        r_mat2 = self.client.get("/api/soc/mitre-matrix", headers=analyst_headers)
        self.assertEqual(r_mat2.get_json()["mitigated_techniques"], 0)

        # 5. Analyst verifies containment
        r_ver = self.client.post(f"/api/soc/response-actions/{action_id}/verify", headers=analyst_headers)
        self.assertEqual(r_ver.status_code, 200)

        # Verify incident transitioned to CONTAINED
        r_inc2 = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_headers)
        self.assertEqual(r_inc2.get_json()["incident"]["status"], "CONTAINED")

        # Verify MITRE matrix now reflects MITIGATED
        r_mat3 = self.client.get("/api/soc/mitre-matrix", headers=analyst_headers)
        self.assertEqual(r_mat3.get_json()["mitigated_techniques"], 1)

    # -------------------------------------------------------------------------
    # 17. Incident Detail UI Markup and Component Structure
    # -------------------------------------------------------------------------
    def test_17_incident_detail_ui_markup(self):
        """Verify the index page renders all refactored incident console UI components."""
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        html = r.data.decode("utf-8")

        # 1. Header & Summary KPI Cards
        self.assertIn('id="detail-incident-id"', html)
        self.assertIn('id="summary-alert-count"', html)
        self.assertIn('id="summary-mitigated-count"', html)
        self.assertIn('id="summary-status-val"', html)
        self.assertIn('id="summary-action-count"', html)

        # 2. Workflow Stepper
        self.assertIn('id="workflow-stepper"', html)
        for step in ["NEW", "TRIAGE", "INVESTIGATING", "CLASSIFIED", "RESPONSE_REQUESTED", "CONTAINMENT_PENDING_APPROVAL", "CONTAINED", "CLOSED"]:
            self.assertIn(f'data-step="{step}"', html)

        # 3. Evidence & Correlated Alerts Table
        self.assertIn('id="table-correlated-alerts"', html)
        self.assertIn('id="correlated-alerts-body"', html)
        self.assertIn('id="ev-message"', html)

        # 4. Containment & Response Console
        self.assertIn('id="btn-wf-request-block"', html)
        self.assertIn('id="incident-actions-container"', html)
        self.assertIn('Containment Safety Notice', html)

        # 5. Timeline & Analyst Notes
        self.assertIn('id="timeline-feed"', html)
        self.assertIn('id="analyst-note-textarea"', html)
        self.assertIn('id="btn-add-note"', html)

        # 6. Compact Secondary Reference Accordion
        self.assertIn('soc-reference-accordion', html)
        self.assertIn('Defensive SOC Rules of Engagement', html)
        self.assertIn('Mitigation Status Criteria', html)

    # -------------------------------------------------------------------------
    # 18. INFO Severity Support and Persistence
    # -------------------------------------------------------------------------
    def test_18_info_severity_support_and_persistence(self):
        """Telemetry sent with severity='info' (e.g. from Secure Portal port probes) is accepted and persists."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        payload = {
            "source_ip": "192.168.31.91",
            "signature": "PORT_SCAN",
            "severity": "info",
            "message": "Port probe connection observed"
        }
        res = self.client.post("/api/events", headers=headers, json=payload)
        self.assertEqual(res.status_code, 202)
        inc_id = res.get_json()["incident_id"]

        with db(self.test_db_path) as c:
            row = c.execute("SELECT * FROM incidents WHERE incident_id=?", (inc_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["severity"], "info")

        # Now send high severity alert for same IP/signature -> severity escalates
        res2 = self.client.post("/api/events", headers=headers, json={
            "source_ip": "192.168.31.91",
            "signature": "PORT_SCAN",
            "severity": "high",
            "message": "Aggressive port sweep"
        })
        self.assertEqual(res2.status_code, 202)
        with db(self.test_db_path) as c:
            row2 = c.execute("SELECT * FROM incidents WHERE incident_id=?", (inc_id,)).fetchone()
            self.assertEqual(row2["severity"], "high")

    # -------------------------------------------------------------------------
    # 19. X-API-Key Header Authentication Support
    # -------------------------------------------------------------------------
    def test_19_x_api_key_header_authentication(self):
        """Endpoints support X-API-Key header in addition to Authorization: Bearer."""
        # Agent endpoint with X-API-Key
        r1 = self.client.post("/api/events", headers={"X-API-Key": TEST_AGENT_TOKEN}, json={
            "source_ip": "10.0.0.77", "signature": "SQL_INJECTION", "severity": "medium"
        })
        self.assertEqual(r1.status_code, 202)

        # Analyst endpoint with X-API-Key
        r2 = self.client.get("/api/soc/mitre-matrix", headers={"X-API-Key": TEST_ANALYST_TOKEN})
        self.assertEqual(r2.status_code, 200)

        # Wrong X-API-Key -> 401
        r3 = self.client.post("/api/events", headers={"X-API-Key": "wrong-key"}, json={
            "source_ip": "10.0.0.77", "signature": "SQL_INJECTION"
        })
        self.assertEqual(r3.status_code, 401)

    # -------------------------------------------------------------------------
    # 20. Extended Portal Signature Normalization & Operational Events
    # -------------------------------------------------------------------------
    def test_20_extended_portal_signature_normalization(self):
        """Portal event types (LOGIN_FAILED, AUTH_BRUTE_FORCE, AUTH_SUCCESS) map accurately."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        # LOGIN_FAILED maps to BRUTE_FORCE_AUTH
        r_lf = self.client.post("/api/events", headers=headers, json={
            "source_ip": "192.168.31.91", "event_type": "LOGIN_FAILED"
        })
        self.assertEqual(r_lf.status_code, 202)
        self.assertEqual(r_lf.get_json()["signature"], "BRUTE_FORCE_AUTH")

        # AUTH_BRUTE_FORCE maps to BRUTE_FORCE_AUTH
        r_abf = self.client.post("/api/events", headers=headers, json={
            "source_ip": "192.168.31.91", "event_type": "AUTH_BRUTE_FORCE"
        })
        self.assertEqual(r_abf.status_code, 202)
        self.assertEqual(r_abf.get_json()["signature"], "BRUTE_FORCE_AUTH")

        # AUTH_SUCCESS is acknowledged as operational telemetry without creating alerts
        r_as = self.client.post("/api/events", headers=headers, json={
            "source_ip": "192.168.31.91", "event_type": "AUTH_SUCCESS"
        })
        self.assertEqual(r_as.status_code, 202)
        self.assertEqual(r_as.get_json()["event_type"], "auth_success")

    # -------------------------------------------------------------------------
    # 21. Startup Configuration Validation Actionability
    # -------------------------------------------------------------------------
    def test_21_startup_configuration_validation_actionability(self):
        """validate_startup_config validates secrets, ports, paths without leaking secret values."""
        # 1. Valid configuration succeeds
        conf = validate_startup_config()
        self.assertTrue(conf["agent_auth_configured"])
        self.assertEqual(conf["agent_token_len"], len(TEST_AGENT_TOKEN))
        self.assertTrue(conf["analyst_auth_configured"])
        self.assertEqual(conf["analyst_token_len"], len(TEST_ANALYST_TOKEN))

        # 2. Missing agent token raises SystemExit
        orig_agent = app.config.get("SOC_AGENT_TOKEN")
        try:
            app.config["SOC_AGENT_TOKEN"] = ""
            saved_env = os.environ.pop("SOC_AGENT_TOKEN", None)
            saved_key = os.environ.pop("SOC_API_KEY", None)
            with self.assertRaises(SystemExit) as ctx:
                validate_startup_config()
            self.assertIn("Missing agent authentication token", str(ctx.exception))
            if saved_env: os.environ["SOC_AGENT_TOKEN"] = saved_env
            if saved_key: os.environ["SOC_API_KEY"] = saved_key
        finally:
            app.config["SOC_AGENT_TOKEN"] = orig_agent

        # 3. Placeholder agent token raises SystemExit
        try:
            app.config["SOC_AGENT_TOKEN"] = "replace_with_random_agent_secret"
            with self.assertRaises(SystemExit) as ctx:
                validate_startup_config()
            self.assertIn("Placeholder agent token detected", str(ctx.exception))
        finally:
            app.config["SOC_AGENT_TOKEN"] = orig_agent

        # 4. Invalid port raises SystemExit
        orig_port = app.config.get("SOC_PORT")
        try:
            app.config["SOC_PORT"] = "999999"
            with self.assertRaises(SystemExit) as ctx:
                validate_startup_config()
            self.assertIn("Invalid SOC_PORT", str(ctx.exception))
        finally:
            if orig_port is not None: app.config["SOC_PORT"] = orig_port
            else: app.config.pop("SOC_PORT", None)

    # -------------------------------------------------------------------------
    # 22. Ingestion of All Six Attack Signatures and MITRE ATT&CK Mapping
    # -------------------------------------------------------------------------
    def test_22_all_six_attack_signatures_ingestion_and_mitre_mapping(self):
        """All 6 core portal attack signatures ingest, persist, and map to expected MITRE IDs."""
        headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        expected_mappings = {
            "PORT_SCAN": "T1046",
            "DIR_FUZZ": "T1083",
            "PATH_TRAVERSAL": "T1083",
            "SQL_INJECTION": "T1190",
            "BRUTE_FORCE_AUTH": "T1110",
            "COMMAND_INJECTION": "T1059",
        }

        for idx, (sig, expected_tid) in enumerate(expected_mappings.items(), start=1):
            ip = f"192.168.31.{100 + idx}"
            res = self.client.post("/api/events", headers=headers, json={
                "source_ip": ip,
                "signature": sig,
                "severity": "medium",
                "message": f"Test verification for {sig}"
            })
            self.assertEqual(res.status_code, 202, f"Failed for {sig}")
            data = res.get_json()
            self.assertEqual(data["mitre_id"], expected_tid)
            self.assertEqual(data["signature"], sig)

            # Confirm persistent storage in SQLite
            with db(self.test_db_path) as c:
                row = c.execute("SELECT * FROM alerts WHERE source_ip=? AND signature=?", (ip, sig)).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row["mitre_id"], expected_tid)

    # -------------------------------------------------------------------------
    # 23. Reliable Directory-Discovery (DIR_FUZZ) Detection & Metadata Preservation
    # -------------------------------------------------------------------------
    def test_23_directory_discovery_fuzz_detection(self):
        """
        Comprehensive validation of DIR_FUZZ detection:
        a. Explicit suspicious path triggers immediate DIR_FUZZ alert with T1083.
        b. Benign paths (/favicon.ico, /robots.txt, /static/*) are safely suppressed.
        c. Repeated distinct 404 path probes trigger threshold escalation.
        d. HTTP telemetry metadata (method, path, status, reason) is fully preserved.
        e. Duplicate event_id submissions are safely idempotent.
        f. Configurable threshold and window via environment / app.config.
        g. Client DIR_FUZZ labels with benign paths are not blindly trusted.
        """
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        # ---------------------------------------------------------------------
        # (a) Explicit suspicious path -> Immediate DIR_FUZZ alert (T1083)
        # ---------------------------------------------------------------------
        res_exp = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "192.168.31.201",
            "event_type": "HTTP_404",
            "path": "/.env",
            "method": "GET",
            "response_status": 404
        })
        self.assertEqual(res_exp.status_code, 202)
        data_exp = res_exp.get_json()
        self.assertEqual(data_exp["status"], "accepted")
        self.assertEqual(data_exp["signature"], "DIR_FUZZ")
        self.assertEqual(data_exp["mitre_id"], "T1083")
        inc_id_exp = data_exp["incident_id"]

        with db(self.test_db_path) as c:
            alert_exp = c.execute("SELECT * FROM alerts WHERE source_ip='192.168.31.201'").fetchone()
            self.assertIsNotNone(alert_exp)
            self.assertEqual(alert_exp["signature"], "DIR_FUZZ")
            self.assertEqual(alert_exp["mitre_id"], "T1083")
            self.assertEqual(alert_exp["http_method"], "GET")
            self.assertEqual(alert_exp["requested_path"], "/.env")
            self.assertEqual(alert_exp["response_status"], 404)
            self.assertIn("Explicit sensitive discovery target", alert_exp["detection_reason"])
            self.assertEqual(alert_exp["severity"], "high")

            inc_exp = c.execute("SELECT * FROM incidents WHERE incident_id=?", (inc_id_exp,)).fetchone()
            self.assertIsNotNone(inc_exp)
            self.assertEqual(inc_exp["signature"], "DIR_FUZZ")
            self.assertEqual(inc_exp["status"], "NEW")

        # ---------------------------------------------------------------------
        # (b) Benign paths -> Suppressed without attack alerts (False-Positive Safeguards)
        # ---------------------------------------------------------------------
        benign_test_cases = [
            "/favicon.ico",
            "/robots.txt",
            "/sitemap.xml",
            "/static/css/dashboard_component.css",
            "/static/js/dashboard_component.js",
            "/assets/logo.png"
        ]
        for bpath in benign_test_cases:
            r_benign = self.client.post("/api/events", headers=agent_headers, json={
                "source_ip": "192.168.31.202",
                "event_type": "HTTP_404",
                "path": bpath,
                "method": "GET",
                "response_status": 404
            })
            self.assertEqual(r_benign.status_code, 202)
            self.assertEqual(r_benign.get_json()["event_type"], "benign_path_suppressed")

        # Confirm zero alerts recorded for the benign IP
        with db(self.test_db_path) as c:
            b_cnt = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip='192.168.31.202'").fetchone()[0]
            self.assertEqual(b_cnt, 0)

        # ---------------------------------------------------------------------
        # (c) Repeated distinct 404 paths -> Threshold escalation
        # ---------------------------------------------------------------------
        target_fuzz_ip = "192.168.31.203"
        # Probe 1: non-suspicious missing page
        r_p1 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_fuzz_ip, "event_type": "HTTP_404", "path": "/page-one-missing", "method": "GET"
        })
        self.assertEqual(r_p1.status_code, 202)
        self.assertEqual(r_p1.get_json()["event_type"], "probe_recorded")
        self.assertEqual(r_p1.get_json()["distinct_probes"], 1)

        # Duplicate probe for the same path does NOT increment distinct count
        r_p1_dup = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_fuzz_ip, "event_type": "HTTP_404", "path": "/page-one-missing", "method": "GET"
        })
        self.assertEqual(r_p1_dup.status_code, 202)
        self.assertEqual(r_p1_dup.get_json()["distinct_probes"], 1)

        # Still 0 alerts in database
        with db(self.test_db_path) as c:
            cnt0 = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip=?", (target_fuzz_ip,)).fetchone()[0]
            self.assertEqual(cnt0, 0)

        # Probe 2: second distinct missing page
        r_p2 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_fuzz_ip, "event_type": "HTTP_404", "path": "/page-two-missing", "method": "GET"
        })
        self.assertEqual(r_p2.status_code, 202)
        self.assertEqual(r_p2.get_json()["distinct_probes"], 2)

        # Still 0 alerts in database
        with db(self.test_db_path) as c:
            cnt1 = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip=?", (target_fuzz_ip,)).fetchone()[0]
            self.assertEqual(cnt1, 0)

        # Probe 3: third distinct missing page -> reaches threshold 3 -> triggers DIR_FUZZ alert!
        r_p3 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_fuzz_ip, "event_type": "HTTP_404", "path": "/page-three-missing", "method": "GET"
        })
        self.assertEqual(r_p3.status_code, 202)
        d_p3 = r_p3.get_json()
        self.assertEqual(d_p3["signature"], "DIR_FUZZ")
        self.assertEqual(d_p3["mitre_id"], "T1083")
        fuzz_inc_id = d_p3["incident_id"]

        with db(self.test_db_path) as c:
            alerts_fuzz = c.execute("SELECT * FROM alerts WHERE source_ip=?", (target_fuzz_ip,)).fetchall()
            self.assertEqual(len(alerts_fuzz), 1)
            self.assertEqual(alerts_fuzz[0]["signature"], "DIR_FUZZ")
            self.assertIn("Threshold exceeded", alerts_fuzz[0]["detection_reason"])

        # Probe 4: subsequent probe in same window correlates into existing incident
        r_p4 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_fuzz_ip, "event_type": "HTTP_404", "path": "/page-four-missing", "method": "GET"
        })
        self.assertEqual(r_p4.status_code, 202)
        self.assertEqual(r_p4.get_json()["incident_id"], fuzz_inc_id)

        with db(self.test_db_path) as c:
            alerts_fuzz2 = c.execute("SELECT * FROM alerts WHERE source_ip=?", (target_fuzz_ip,)).fetchall()
            self.assertEqual(len(alerts_fuzz2), 2)

        # ---------------------------------------------------------------------
        # (d) Telemetry metadata preservation & Explicit/Missing/Malformed/Out-of-range status
        # ---------------------------------------------------------------------
        # Case 1: Explicit valid status (404, 403)
        r_meta = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "192.168.31.204",
            "event_type": "DIRECTORY_DISCOVERY",
            "path": "/wp-login.php",
            "method": "POST",
            "response_status": 403,
            "reason": "Suspicious login discovery endpoint probed"
        })
        self.assertEqual(r_meta.status_code, 202)
        meta_inc_id = r_meta.get_json()["incident_id"]

        r_inc_detail = self.client.get(f"/api/soc/incidents/{meta_inc_id}", headers=analyst_headers)
        self.assertEqual(r_inc_detail.status_code, 200)
        inc_data = r_inc_detail.get_json()["incident"]
        self.assertEqual(len(inc_data["correlated_alerts"]), 1)
        alert_item = inc_data["correlated_alerts"][0]
        self.assertEqual(alert_item["source_ip"], "192.168.31.204")
        self.assertEqual(alert_item["http_method"], "POST")
        self.assertEqual(alert_item["requested_path"], "/wp-login.php")
        self.assertEqual(alert_item["response_status"], 403)
        self.assertIn("Suspicious login discovery endpoint probed", alert_item["detection_reason"])

        # Case 2: Missing response_status -> falls back safely to default without error
        r_miss_status = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "192.168.31.210",
            "event_type": "HTTP_404",
            "path": "/.git/config"
        })
        self.assertEqual(r_miss_status.status_code, 202)
        with db(self.test_db_path) as c:
            a_row = c.execute("SELECT response_status FROM alerts WHERE source_ip='192.168.31.210'").fetchone()
            self.assertEqual(a_row["response_status"], 404)

        # Case 3: Malformed response_status string -> sanitized to None without 500 error
        r_malformed = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "192.168.31.211",
            "event_type": "DIR_FUZZ",
            "path": "/admin/config.php",
            "response_status": "not-a-number"
        })
        self.assertEqual(r_malformed.status_code, 202)
        with db(self.test_db_path) as c:
            a_row = c.execute("SELECT response_status FROM alerts WHERE source_ip='192.168.31.211'").fetchone()
            self.assertIsNone(a_row["response_status"])

        # Case 4: Out-of-range status codes (<100 or >599) -> sanitized to None
        for bad_code in [-1, 0, 99, 600, 9999]:
            r_oor = self.client.post("/api/events", headers=agent_headers, json={
                "source_ip": "192.168.31.212",
                "event_type": "DIR_FUZZ",
                "path": "/admin/settings.php",
                "response_status": bad_code
            })
            self.assertEqual(r_oor.status_code, 202)
        with db(self.test_db_path) as c:
            oor_rows = c.execute("SELECT response_status FROM alerts WHERE source_ip='192.168.31.212'").fetchall()
            for r in oor_rows:
                self.assertIsNone(r["response_status"])

        # ---------------------------------------------------------------------
        # (e) Event ID Idempotency & Repeated Event ID Probe Non-Escalation
        # ---------------------------------------------------------------------
        fixed_evt_id = "fuzz-unique-event-id-8888"
        dup_payload = {
            "event_id": fixed_evt_id,
            "source_ip": "192.168.31.205",
            "event_type": "HTTP_404",
            "path": "/admin/backup.sql",
            "method": "GET",
            "response_status": 404
        }
        res_first = self.client.post("/api/events", headers=agent_headers, json=dup_payload)
        self.assertEqual(res_first.status_code, 202)
        first_inc = res_first.get_json()["incident_id"]

        # Duplicate re-submission of alert event
        res_second = self.client.post("/api/events", headers=agent_headers, json=dup_payload)
        self.assertEqual(res_second.status_code, 202)
        self.assertEqual(res_second.get_json()["incident_id"], first_inc)
        self.assertEqual(res_second.get_json()["event_id"], fixed_evt_id)

        with db(self.test_db_path) as c:
            dup_cnt = c.execute("SELECT COUNT(*) FROM alerts WHERE event_id=?", (fixed_evt_id,)).fetchone()[0]
            self.assertEqual(dup_cnt, 1, "Duplicate event_id must not create duplicate alert rows")

        # Prove repeated event IDs do NOT increment distinct-probe counts or trigger threshold escalation
        fuzz_probe_ip = "192.168.31.220"
        probe_evt_1 = "probe-evt-token-111"

        # Send probe with event_id
        r_prb1 = self.client.post("/api/events", headers=agent_headers, json={
            "event_id": probe_evt_1,
            "source_ip": fuzz_probe_ip,
            "event_type": "HTTP_404",
            "path": "/random-test-alpha",
            "response_status": 404
        })
        self.assertEqual(r_prb1.status_code, 202)
        self.assertEqual(r_prb1.get_json()["distinct_probes"], 1)

        # Resend exact same event_id 3 times -> distinct probes must remain 1 and NOT escalate to attack
        for _ in range(3):
            r_prb_resend = self.client.post("/api/events", headers=agent_headers, json={
                "event_id": probe_evt_1,
                "source_ip": fuzz_probe_ip,
                "event_type": "HTTP_404",
                "path": "/random-test-alpha",
                "response_status": 404
            })
            self.assertEqual(r_prb_resend.status_code, 202)
            self.assertEqual(r_prb_resend.get_json()["distinct_probes"], 1)

        # Confirm 0 alerts in database for this IP (re-sent event_id did not trigger threshold)
        with db(self.test_db_path) as c:
            p_alerts = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip=?", (fuzz_probe_ip,)).fetchone()[0]
            self.assertEqual(p_alerts, 0)

        # ---------------------------------------------------------------------
        # (f) Untrusted Client DIR_FUZZ label with benign path -> Safely suppressed
        # ---------------------------------------------------------------------
        r_untrusted = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": "192.168.31.206",
            "signature": "DIR_FUZZ",
            "path": "/favicon.ico",
            "method": "GET"
        })
        self.assertEqual(r_untrusted.status_code, 202)
        self.assertEqual(r_untrusted.get_json()["event_type"], "benign_path_suppressed")
        with db(self.test_db_path) as c:
            u_cnt = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip='192.168.31.206'").fetchone()[0]
            self.assertEqual(u_cnt, 0)

        # ---------------------------------------------------------------------
        # (g) Backup file extension triggers (.bak, .sql, .tar.gz)
        # ---------------------------------------------------------------------
        for ext_path in ["/dump.sql", "/archive.tar.gz", "/db_backup.zip", "/config.php.bak"]:
            r_ext = self.client.post("/api/events", headers=agent_headers, json={
                "source_ip": "192.168.31.207",
                "event_type": "HTTP_404",
                "path": ext_path
            })
            self.assertEqual(r_ext.status_code, 202)
            self.assertEqual(r_ext.get_json()["signature"], "DIR_FUZZ")
            self.assertEqual(r_ext.get_json()["mitre_id"], "T1083")

    # -------------------------------------------------------------------------
    # 24. Tracker Expiration and Maximum Tracked Sources Bounding
    # -------------------------------------------------------------------------
    def test_24_tracker_expiration_and_capacity_bounding(self):
        """Test probe tracker sliding-window expiration and memory bounding under scale."""
        # 1. Time-window expiration: older probes expire and do not count toward threshold
        test_ip = "10.80.0.1"
        reset_dir_fuzz_tracker()

        # Probe 1 at t=100s
        is_att1, count1, _ = probe_tracker.record_probe(
            source_ip=test_ip, path="/probe1", threshold=3, window_seconds=60, current_time=100.0
        )
        self.assertFalse(is_att1)
        self.assertEqual(count1, 1)

        # Probe 2 at t=120s (within 60s window) -> count = 2
        is_att2, count2, _ = probe_tracker.record_probe(
            source_ip=test_ip, path="/probe2", threshold=3, window_seconds=60, current_time=120.0
        )
        self.assertFalse(is_att2)
        self.assertEqual(count2, 2)

        # Probe 3 at t=170s (t=100s probe has expired, but t=120s is still valid) -> count = 2 (not 3)
        is_att3, count3, _ = probe_tracker.record_probe(
            source_ip=test_ip, path="/probe3", threshold=3, window_seconds=60, current_time=170.0
        )
        self.assertFalse(is_att3)
        self.assertEqual(count3, 2, "Expired probe at t=100s must be pruned out of the 60s sliding window")

        # 2. Maximum tracked sources capacity bounding
        reset_dir_fuzz_tracker()
        max_sources_test = 5
        # Record probes across 10 distinct source IPs
        for i in range(1, 11):
            probe_tracker.record_probe(
                source_ip=f"10.80.1.{i}",
                path=f"/scan-{i}",
                threshold=3,
                window_seconds=60,
                max_sources=max_sources_test
            )

        # Active tracked IPs must be strictly bounded to max_sources_test
        self.assertLessEqual(
            len(probe_tracker._probes),
            max_sources_test,
            f"Tracker probe memory must not exceed max_sources ({max_sources_test})"
        )

    # -------------------------------------------------------------------------
    # 25. Source IP Isolation (No Cross-Contamination of Probe Thresholds)
    # -------------------------------------------------------------------------
    def test_25_source_ip_isolation(self):
        """Probes from different source IPs are tracked independently and do not cross-contaminate."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        ip_a = "10.90.0.1"
        ip_b = "10.90.0.2"

        # IP A probes 2 distinct paths (below threshold 3)
        for p in ["/alpha-1", "/alpha-2"]:
            r = self.client.post("/api/events", headers=agent_headers, json={
                "source_ip": ip_a, "event_type": "HTTP_404", "path": p, "response_status": 404
            })
            self.assertEqual(r.status_code, 202)
            self.assertEqual(r.get_json()["event_type"], "probe_recorded")

        # IP B probes 2 distinct paths (below threshold 3)
        for p in ["/beta-1", "/beta-2"]:
            r = self.client.post("/api/events", headers=agent_headers, json={
                "source_ip": ip_b, "event_type": "HTTP_404", "path": p, "response_status": 404
            })
            self.assertEqual(r.status_code, 202)
            self.assertEqual(r.get_json()["event_type"], "probe_recorded")

        # Verify neither IP reached threshold and 0 alerts exist for both IPs
        with db(self.test_db_path) as c:
            cnt_a = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip=?", (ip_a,)).fetchone()[0]
            cnt_b = c.execute("SELECT COUNT(*) FROM alerts WHERE source_ip=?", (ip_b,)).fetchone()[0]
            self.assertEqual(cnt_a, 0)
            self.assertEqual(cnt_b, 0)

    # -------------------------------------------------------------------------
    # 26. Incident Severity Non-Regression
    # -------------------------------------------------------------------------
    def test_26_incident_severity_non_regression(self):
        """Incident severity escalates on higher-severity alerts but never regresses on lower-severity alerts."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "10.95.0.1"

        # 1. First alert with 'high' severity
        r1 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_ip, "signature": "SQL_INJECTION", "severity": "high"
        })
        self.assertEqual(r1.status_code, 202)
        inc_id = r1.get_json()["incident_id"]

        with db(self.test_db_path) as c:
            row1 = c.execute("SELECT severity FROM incidents WHERE incident_id=?", (inc_id,)).fetchone()
            self.assertEqual(row1["severity"], "high")

        # 2. Correlating alert with 'low' severity arrives -> incident severity MUST remain 'high'
        r2 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_ip, "signature": "SQL_INJECTION", "severity": "low"
        })
        self.assertEqual(r2.status_code, 202)
        self.assertEqual(r2.get_json()["incident_id"], inc_id)

        with db(self.test_db_path) as c:
            row2 = c.execute("SELECT severity FROM incidents WHERE incident_id=?", (inc_id,)).fetchone()
            self.assertEqual(row2["severity"], "high", "Incident severity must not regress from high to low")

        # 3. Correlating alert with 'critical' severity arrives -> incident escalates to 'critical'
        r3 = self.client.post("/api/events", headers=agent_headers, json={
            "source_ip": target_ip, "signature": "SQL_INJECTION", "severity": "critical"
        })
        self.assertEqual(r3.status_code, 202)
        self.assertEqual(r3.get_json()["incident_id"], inc_id)

        with db(self.test_db_path) as c:
            row3 = c.execute("SELECT severity FROM incidents WHERE incident_id=?", (inc_id,)).fetchone()
            self.assertEqual(row3["severity"], "critical")

    # -------------------------------------------------------------------------
    # 27. Unauthorized Containment Approval and Invalid Response-Action Transitions
    # -------------------------------------------------------------------------
    def test_27_unauthorized_containment_and_invalid_action_transitions(self):
        """Validate RBAC authorization and state machine transitions on containment actions."""
        agent_headers = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "10.99.0.77"

        # Step 1: Analyst queues block action -> state is PENDING
        r_block = self.client.post("/api/soc/mitigate/block", headers=analyst_headers, json={
            "target_ip": target_ip, "timeout_seconds": 3600
        })
        self.assertEqual(r_block.status_code, 202)
        action_id = r_block.get_json()["action_id"]

        # Step 2: Unauthenticated request to approve -> 401
        r_unauth_app = self.client.post(f"/api/soc/response-actions/{action_id}/approve")
        self.assertEqual(r_unauth_app.status_code, 401)

        # Step 3: Agent token cannot approve containment action -> 401
        r_agent_app = self.client.post(f"/api/soc/response-actions/{action_id}/approve", headers=agent_headers)
        self.assertEqual(r_agent_app.status_code, 401)

        # Step 4: Invalid action ID -> 404
        r_not_found = self.client.post("/api/soc/response-actions/999999/approve", headers=analyst_headers)
        self.assertEqual(r_not_found.status_code, 404)

        # Step 5: Valid approval by analyst -> 200 (state: APPROVED)
        r_app = self.client.post(f"/api/soc/response-actions/{action_id}/approve", headers=analyst_headers)
        self.assertEqual(r_app.status_code, 200)
        self.assertEqual(r_app.get_json()["status"], "APPROVED")

        # Step 6: Second approval on already APPROVED action -> 404 (not PENDING)
        r_app_again = self.client.post(f"/api/soc/response-actions/{action_id}/approve", headers=analyst_headers)
        self.assertEqual(r_app_again.status_code, 404)

        # Step 7: Agent reports status with invalid status state -> 400
        r_bad_status = self.client.post("/api/agent/action-status", headers=agent_headers, json={
            "action_id": action_id, "status": "NON_EXISTENT_STATE"
        })
        self.assertEqual(r_bad_status.status_code, 400)

        # Step 8: Analyst tries to verify action on non-existent action -> 404
        r_bad_verify = self.client.post("/api/soc/response-actions/999999/verify", headers=analyst_headers)
        self.assertEqual(r_bad_verify.status_code, 404)

    # -------------------------------------------------------------------------
    # 28. Defense Status Transitions (Detected -> Applied -> Pending -> Verified -> Expired)
    # -------------------------------------------------------------------------
    def test_28_defense_status_transitions(self):
        """Test full defense status lifecycle: Detected -> Mitigation Applied -> Verification Pending -> Verified."""
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "198.51.100.41"

        # 1. Ingest alert -> status is DETECTED
        r1 = self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip,
            "signature": "SQL_INJECTION",
            "severity": "high",
            "message": "SELECT * FROM users WHERE id=' OR '1'='1"
        })
        self.assertEqual(r1.status_code, 202)
        inc_id = r1.get_json()["incident_id"]

        r_inc = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertEqual(r_inc.status_code, 200)
        self.assertEqual(r_inc.get_json()["incident"]["defense_status"], "Detected")

        # 2. Queue containment action -> PENDING
        r_block = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": target_ip, "incident_id": inc_id, "timeout_seconds": 600
        })
        self.assertEqual(r_block.status_code, 202)
        aid = r_block.get_json()["action_id"]

        # 3. Approve action -> APPROVED
        r_app = self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.assertEqual(r_app.status_code, 200)

        # 4. Agent reports execution / mitigation applied -> MITIGATION_APPLIED
        r_exec = self.client.post("/api/agent/action-status", headers=agent_h, json={
            "action_id": aid, "status": "MITIGATION_APPLIED", "message": "nftables rule appended"
        })
        self.assertEqual(r_exec.status_code, 200)

        r_inc2 = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertEqual(r_inc2.get_json()["incident"]["defense_status"], "Mitigation Applied")

        # 5. Analyst marks verification pending -> VERIFICATION_PENDING
        r_pend = self.client.post(f"/api/soc/response-actions/{aid}/pending-verification", headers=analyst_h)
        self.assertEqual(r_pend.status_code, 200)

        r_inc3 = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertEqual(r_inc3.get_json()["incident"]["defense_status"], "Verification Pending")

        # 6. Verify with authentic nftables evidence -> VERIFIED
        nft_proof = f"""
        table inet filter {{
            set blocked_ips {{
                type ipv4_addr
                elements = {{ {target_ip} }}
            }}
        }}
        """
        r_ver = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": nft_proof
        })
        self.assertEqual(r_ver.status_code, 200)
        self.assertTrue(r_ver.get_json()["verified"])
        self.assertEqual(r_ver.get_json()["status"], "VERIFIED")

        r_inc4 = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertEqual(r_inc4.get_json()["incident"]["defense_status"], "Verified")

        # Verify matrix reflects MITIGATED
        r_mat = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        item = next(x for x in r_mat.get_json()["matrix"] if x["signature"] == "SQL_INJECTION")
        self.assertEqual(item["state"], "MITIGATED")
        self.assertGreaterEqual(item["mitigated_count"], 1)

    # -------------------------------------------------------------------------
    # 29. Verification Evidence Validation & Fraud Prevention
    # -------------------------------------------------------------------------
    def test_29_evidence_validation(self):
        """Test verification evidence validation: rejects simulation/mismatches, accepts valid proofs."""
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "198.51.100.52"

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "COMMAND_INJECTION", "severity": "high"
        })
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={"target_ip": target_ip})
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        # A: Reject dry-run / simulation without kernel proof
        r_dry = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": "[DRY_RUN] Simulated containment executed without nftables kernel modification."
        })
        self.assertEqual(r_dry.status_code, 200)
        self.assertFalse(r_dry.get_json()["verified"])
        self.assertEqual(r_dry.get_json()["status"], "VERIFICATION_FAILED")

        # B: Reject evidence with target IP mismatch
        r_mismatch = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": "table inet filter { set blocked_ips { elements = { 10.0.0.99 } } }"
        })
        self.assertEqual(r_mismatch.status_code, 200)
        self.assertFalse(r_mismatch.get_json()["verified"])
        self.assertEqual(r_mismatch.get_json()["status"], "VERIFICATION_FAILED")
        self.assertTrue(
            "does not match" in r_mismatch.get_json()["error"] or "do not contain" in r_mismatch.get_json()["error"]
        )

        # C: Accept authentic proof with matching target IP
        r_valid = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ elements = {{ {target_ip} }} }} }}"
        })
        self.assertEqual(r_valid.status_code, 200)
        self.assertTrue(r_valid.get_json()["verified"])
        self.assertEqual(r_valid.get_json()["status"], "VERIFIED")

    # -------------------------------------------------------------------------
    # 30. Duplicate Events Deduplication & Idempotency
    # -------------------------------------------------------------------------
    def test_30_duplicate_events(self):
        """Test idempotent deduplication with identical event_id preserving state."""
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        unique_eid = "dup_test_event_998877"
        target_ip = "198.51.100.63"

        # First ingestion
        r1 = self.client.post("/api/events", headers=agent_h, json={
            "event_id": unique_eid,
            "source_ip": target_ip,
            "signature": "PORT_SCAN",
            "severity": "medium",
            "message": "Initial port probe"
        })
        self.assertEqual(r1.status_code, 202)
        orig_inc = r1.get_json()["incident_id"]

        # Duplicate ingestion with same event_id
        r2 = self.client.post("/api/events", headers=agent_h, json={
            "event_id": unique_eid,
            "source_ip": target_ip,
            "signature": "PORT_SCAN",
            "severity": "medium",
            "message": "Duplicate port probe transmission"
        })
        self.assertEqual(r2.status_code, 202)
        self.assertEqual(r2.get_json()["event_id"], unique_eid)
        self.assertEqual(r2.get_json()["incident_id"], orig_inc)

        # Check alert count for this incident is exactly 1
        r_alerts = self.client.get(f"/api/soc/alerts?source_ip={target_ip}", headers=analyst_h)
        self.assertEqual(r_alerts.status_code, 200)
        matching = [a for a in r_alerts.get_json()["alerts"] if a["event_id"] == unique_eid]
        self.assertEqual(len(matching), 1)

    # -------------------------------------------------------------------------
    # 31. Temporary Controls and Automatic Expiry
    # -------------------------------------------------------------------------
    def test_31_temporary_controls_and_expiry(self):
        """Test temporary control countdown, expiry transition, and exclusion from verified mitigation count."""
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "198.51.100.74"

        # Ingest PATH_TRAVERSAL
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "PATH_TRAVERSAL", "severity": "high"
        })

        # Queue temporary block with 30s timeout
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": target_ip, "timeout_seconds": 30
        })
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        # Verify action
        r_v = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ elements = {{ {target_ip} }} }} }}"
        })
        self.assertTrue(r_v.get_json()["verified"])

        # Check temporary controls endpoint: active
        r_temp = self.client.get("/api/soc/temporary-controls", headers=analyst_h)
        self.assertEqual(r_temp.status_code, 200)
        self.assertTrue(any(a["action_id"] == aid and not a["is_expired"] for a in r_temp.get_json()["active_controls"]))

        # Check matrix: MITIGATED
        r_m1 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        item1 = next(x for x in r_m1.get_json()["matrix"] if x["signature"] == "PATH_TRAVERSAL")
        self.assertEqual(item1["state"], "MITIGATED")
        self.assertGreaterEqual(item1["mitigated_count"], 1)

        # Simulate expiration by rewinding timestamps in database
        past_ts = "2020-01-01T00:00:00Z"
        with db() as c:
            c.execute("UPDATE response_actions SET created_at = ?, executed_at = ? WHERE action_id = ?",
                      (past_ts, past_ts, aid))

        # Check matrix after expiration: must NOT count as mitigated!
        r_m2 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        item2 = next(x for x in r_m2.get_json()["matrix"] if x["signature"] == "PATH_TRAVERSAL")
        self.assertEqual(item2["mitigated_count"], 0)
        self.assertIn(item2["state"], ("EXPIRED", "DETECTED"))

        # Check response actions list: action is marked expired
        r_acts = self.client.get("/api/soc/response-actions", headers=analyst_h)
        act_row = next(a for a in r_acts.get_json()["actions"] if a["action_id"] == aid)
        self.assertTrue(act_row["is_expired"])
        self.assertEqual(act_row["defense_status"], "Expired")

    # -------------------------------------------------------------------------
    # 32. Failed Verification & Incident Closure Protection
    # -------------------------------------------------------------------------
    def test_32_failed_verification_and_closure_protection(self):
        """Closing an incident must NEVER mark it verified without independent proof."""
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "198.51.100.85"

        r = self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "BRUTE_FORCE_AUTH", "severity": "medium"
        })
        inc_id = r.get_json()["incident_id"]

        # Close incident with valid rationale
        r_close = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_h, json={
            "status": "CLOSED",
            "rationale": "Analyst determined source stopped attempting auth."
        })
        self.assertEqual(r_close.status_code, 200)
        self.assertEqual(r_close.get_json()["new_status"], "CLOSED")

        # Verify defense status does NOT become 'Verified' merely because incident is closed!
        r_inc = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertNotEqual(r_inc.get_json()["incident"]["defense_status"], "Verified")

        # MITRE matrix must still show mitigated_count = 0
        r_m = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        item = next(x for x in r_m.get_json()["matrix"] if x["signature"] == "BRUTE_FORCE_AUTH")
        self.assertEqual(item["mitigated_count"], 0)
        self.assertNotEqual(item["state"], "MITIGATED")

    # -------------------------------------------------------------------------
    # 33. Secure Portal Rich Metadata Consumption
    # -------------------------------------------------------------------------
    def test_33_secure_portal_rich_metadata_consumption(self):
        """Verify the dashboard backend stores and returns Secure Portal's rich telemetry and metadata."""
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "198.51.100.96"

        portal_event = {
            "source_ip": target_ip,
            "signature": "PORT_SCAN",
            "severity": "medium",
            "destination_ip": "10.0.0.5",
            "destination_port": 80,
            "protocol": "TCP",
            "metadata": {
                "distinct_ports_count": 14,
                "observed_ports": [22, 80, 443, 8080, 8443],
                "duration_seconds": 2.5,
                "tcp_flags": ["SYN"],
                "trigger": "SYN probe burst threshold exceeded"
            }
        }

        r = self.client.post("/api/events", headers=agent_h, json=portal_event)
        self.assertEqual(r.status_code, 202)
        eid = r.get_json()["event_id"]
        inc_id = r.get_json()["incident_id"]

        # Fetch alert list and incident details
        r_al = self.client.get(f"/api/soc/alerts?source_ip={target_ip}", headers=analyst_h)
        self.assertEqual(r_al.status_code, 200)
        alt = next(a for a in r_al.get_json()["alerts"] if a["event_id"] == eid)
        self.assertEqual(alt["destination_ip"], "10.0.0.5")
        self.assertEqual(alt["destination_port"], 80)
        self.assertEqual(alt["protocol"], "TCP")
        self.assertEqual(alt["metadata"]["distinct_ports_count"], 14)
        self.assertEqual(alt["metadata"]["trigger"], "SYN probe burst threshold exceeded")

        r_inc = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertEqual(r_inc.status_code, 200)
        inc_alt = r_inc.get_json()["alerts"][0]
        self.assertEqual(inc_alt["destination_ip"], "10.0.0.5")

    # -------------------------------------------------------------------------
    # 34. Response Actions and Temporary Controls Endpoints
    # -------------------------------------------------------------------------
    def test_34_response_actions_and_temporary_controls_endpoints(self):
        """Test /api/soc/response-actions and /api/soc/temporary-controls endpoints."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}

        r_acts = self.client.get("/api/soc/response-actions", headers=analyst_h)
        self.assertEqual(r_acts.status_code, 200)
        data = r_acts.get_json()
        self.assertIn("actions", data)
        self.assertIn("active_temporary_controls_count", data)
        self.assertIn("expired_controls_count", data)
        self.assertIn("verified_count", data)

        r_temp = self.client.get("/api/soc/temporary-controls", headers=analyst_h)
        self.assertEqual(r_temp.status_code, 200)
        tdata = r_temp.get_json()
        self.assertIn("active_controls", tdata)
        self.assertIn("expired_controls", tdata)

    # -------------------------------------------------------------------------
    # 35. Database Initialization and Idempotency
    # -------------------------------------------------------------------------
    def test_35_db_initialization_and_idempotency(self):
        """Test creating a fresh database from scratch, verifying idempotency and schema."""
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "fresh_soc.db")

            # Initial initialization
            init_db(db_path)

            # Verify idempotency by calling init_db again
            init_db(db_path)

            with db(db_path) as c:
                # Verify foreign key integrity
                fks = c.execute("PRAGMA foreign_key_check").fetchall()
                self.assertEqual(len(fks), 0)

                # Verify all tables exist
                tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                for expected_table in ["alerts", "response_actions", "incidents", "incident_notes", "reports"]:
                    self.assertIn(expected_table, tables)

                # Verify columns in incidents
                inc_cols = {r[1] for r in c.execute("PRAGMA table_info(incidents)").fetchall()}
                self.assertIn("defense_status", inc_cols)
                self.assertIn("verification_evidence", inc_cols)
                self.assertIn("status", inc_cols)

                # Verify columns in response_actions
                act_cols = {r[1] for r in c.execute("PRAGMA table_info(response_actions)").fetchall()}
                self.assertIn("verification_evidence", act_cols)
                self.assertIn("verified_at", act_cols)
                self.assertIn("expires_at", act_cols)

    # -------------------------------------------------------------------------
    # 36. Legacy Database Migration and Foreign Key Integrity
    # -------------------------------------------------------------------------
    def test_36_legacy_database_migration_and_foreign_key_integrity(self):
        """Test migration of a legacy database with pre-existing alerts, incidents, notes, and foreign keys."""
        with tempfile.TemporaryDirectory() as td:
            legacy_db = str(Path(td) / "legacy_soc.db")

            # Create pre-migration schema matching the starter baseline
            con = sqlite3.connect(legacy_db)
            con.execute("PRAGMA foreign_keys = ON")
            con.executescript("""
            CREATE TABLE alerts(
              id INTEGER PRIMARY KEY, event_id TEXT UNIQUE, source_ip TEXT NOT NULL,
              signature TEXT NOT NULL, severity TEXT NOT NULL, timestamp TEXT NOT NULL,
              message TEXT NOT NULL DEFAULT '', mitre_id TEXT, incident_id INTEGER REFERENCES incidents(incident_id));

            CREATE TABLE response_actions(
              action_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER,
              target_ip TEXT NOT NULL, action_type TEXT NOT NULL CHECK(action_type IN ('BLOCK_IP','UNBLOCK_IP')),
              status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','EXECUTED','FAILED','CANCELLED','DRY_RUN','VERIFIED')),
              triggered_by TEXT NOT NULL CHECK(triggered_by IN ('AUTO_RULE','SOC_ANALYST')),
              created_at TEXT NOT NULL, executed_at TEXT, timeout_seconds INTEGER,
              message TEXT NOT NULL DEFAULT '');

            CREATE TABLE incidents(
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

            CREATE TABLE incident_notes(
              note_id INTEGER PRIMARY KEY AUTOINCREMENT,
              incident_id INTEGER NOT NULL REFERENCES incidents(incident_id),
              author TEXT NOT NULL DEFAULT 'SOC_ANALYST',
              created_at TEXT NOT NULL,
              note_text TEXT NOT NULL,
              note_type TEXT NOT NULL DEFAULT 'ANALYST_NOTE' CHECK(note_type IN ('ANALYST_NOTE','STATUS_CHANGE','CLASSIFICATION','CONTAINMENT_REQUEST','SYSTEM'))
            );

            CREATE TABLE reports(
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
            """)

            # Insert pre-existing records with foreign key relationships
            con.execute("""
            INSERT INTO incidents (incident_id, title, status, severity, source_ip, signature, created_at, updated_at)
            VALUES (1, 'Legacy Incident 1', 'NEW', 'high', '198.51.100.10', 'SQL_INJECTION', '2026-10-20T10:00:00Z', '2026-10-20T10:00:00Z')
            """)
            con.execute("""
            INSERT INTO incidents (incident_id, title, status, severity, source_ip, signature, created_at, updated_at, closed_at, closure_rationale)
            VALUES (2, 'Legacy Incident 2', 'CLOSED', 'medium', '198.51.100.20', 'PORT_SCAN', '2026-10-20T11:00:00Z', '2026-10-20T12:00:00Z', '2026-10-20T12:00:00Z', 'Resolved')
            """)
            con.execute("""
            INSERT INTO alerts (id, event_id, source_ip, signature, severity, timestamp, message, incident_id)
            VALUES (101, 'evt-101', '198.51.100.10', 'SQL_INJECTION', 'high', '2026-10-20T10:00:00Z', 'SQLi attempt', 1)
            """)
            con.execute("""
            INSERT INTO incident_notes (note_id, incident_id, author, created_at, note_text, note_type)
            VALUES (201, 1, 'SOC_ANALYST', '2026-10-20T10:05:00Z', 'Investigating alert', 'ANALYST_NOTE')
            """)
            con.execute("""
            INSERT INTO reports (report_id, incident_id, title, report_type, summary, findings, created_at)
            VALUES (301, 2, 'Incident 2 Summary', 'INCIDENT_CLOSURE', 'Summary of port scan', 'No impact', '2026-10-20T12:05:00Z')
            """)
            con.execute("""
            INSERT INTO response_actions (action_id, incident_id, target_ip, action_type, status, triggered_by, created_at)
            VALUES (401, 1, '198.51.100.10', 'BLOCK_IP', 'EXECUTED', 'SOC_ANALYST', '2026-10-20T10:10:00Z')
            """)
            con.commit()
            con.close()

            # Execute migration via init_db
            init_db(legacy_db)

            # Execute second time to test idempotency
            init_db(legacy_db)

            # Verify all data and foreign key integrity
            with db(legacy_db) as c:
                fks = c.execute("PRAGMA foreign_key_check").fetchall()
                self.assertEqual(len(fks), 0, f"Foreign key violations after migration: {fks}")

                # Verify row counts preserved
                self.assertEqual(c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 2)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_notes").fetchone()[0], 1)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 1)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0], 1)

                # Verify defense_status column populated properly without altering workflow statuses
                inc1 = dict(c.execute("SELECT * FROM incidents WHERE incident_id = 1").fetchone())
                self.assertEqual(inc1["status"], "NEW")
                self.assertEqual(inc1["defense_status"], "Detected")

                inc2 = dict(c.execute("SELECT * FROM incidents WHERE incident_id = 2").fetchone())
                self.assertEqual(inc2["status"], "CLOSED")
                self.assertEqual(inc2["defense_status"], "Detected")

                # Verify response_actions supports new statuses like EXPIRED
                c.execute("INSERT INTO response_actions (incident_id, target_ip, action_type, status, triggered_by, created_at) VALUES (1, '198.51.100.10', 'BLOCK_IP', 'EXPIRED', 'AUTO_RULE', '2026-10-21T00:00:00Z')")
                c.execute("DELETE FROM response_actions WHERE status = 'EXPIRED' AND incident_id = 1")

    # -------------------------------------------------------------------------
    # 37. Incident Workflow Status vs. Defense Status Separation
    # -------------------------------------------------------------------------
    def test_37_incident_workflow_vs_defense_status_separation(self):
        """Test strict separation of workflow status and defense status, verifying that DETECTED cannot be set as a workflow status."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "198.51.100.77"

        # 1. Database schema CHECK constraint rejection of DETECTED in status column
        with db(self.test_db_path) as c:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("INSERT INTO incidents (title, status, severity, source_ip, signature, created_at, updated_at) VALUES ('Test Invalid', 'DETECTED', 'low', ?, 'PORT_SCAN', '2026-10-21T00:00:00Z', '2026-10-21T00:00:00Z')", (target_ip,))

        # 2. Ingest an alert: initial workflow status must be 'NEW', defense_status must be 'Detected'
        r_ev = self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip,
            "signature": "PORT_SCAN",
            "severity": "medium"
        })
        self.assertEqual(r_ev.status_code, 202)
        inc_id = r_ev.get_json()["incident_id"]

        r_inc = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        self.assertEqual(r_inc.status_code, 200)
        inc_data = r_inc.get_json()["incident"]
        self.assertEqual(inc_data["status"], "NEW")
        self.assertEqual(inc_data["defense_status"], "Detected")

        # 3. Attempting to transition workflow status to 'DETECTED' must be rejected (HTTP 400)
        r_bad_status = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_h, json={
            "status": "DETECTED"
        })
        self.assertEqual(r_bad_status.status_code, 400)
        self.assertIn("Invalid status", r_bad_status.get_json()["error"])

        # 4. Valid workflow status transitions work as expected
        r_triage = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_h, json={
            "status": "TRIAGE"
        })
        self.assertEqual(r_triage.status_code, 200)
        self.assertEqual(r_triage.get_json()["new_status"], "TRIAGE")

        # 5. Closing the incident does NOT falsely mark defense status as 'Verified'
        r_close = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_h, json={
            "status": "CLOSED",
            "rationale": "Closed after investigation without mitigation"
        })
        self.assertEqual(r_close.status_code, 200)
        self.assertEqual(r_close.get_json()["new_status"], "CLOSED")

        r_inc_closed = self.client.get(f"/api/soc/incidents/{inc_id}", headers=analyst_h)
        closed_data = r_inc_closed.get_json()["incident"]
        self.assertEqual(closed_data["status"], "CLOSED")
        self.assertNotEqual(closed_data["defense_status"], "Verified")
        self.assertEqual(closed_data["defense_status"], "Detected")

    # -------------------------------------------------------------------------
    # 38. Valid Temporary Containment Countdown & Expiry Fields
    # -------------------------------------------------------------------------
    def test_38_countdown_calculation_and_expiry_fields(self):
        """Test countdown calculation produces valid seconds remaining and UTC ISO expires_at with Z suffix."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "198.51.100.81"

        # Create incident and approved response action with 1800s timeout
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "BRUTE_FORCE", "severity": "medium"
        })
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": target_ip, "timeout_seconds": 1800
        })
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)

        # Action is executed by agent 300s ago relative to current time
        import time
        from datetime import datetime, timezone
        now_epoch = int(time.time())
        exec_epoch = now_epoch - 300
        exec_iso = datetime.fromtimestamp(exec_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET status = 'EXECUTED', executed_at = ? WHERE action_id = ?", (exec_iso, aid))

        # Test compute_action_expiry with current time = exec_epoch + 300s (5 minutes in)
        with db(self.test_db_path) as c:
            act = dict(c.execute("SELECT * FROM response_actions WHERE action_id = ?", (aid,)).fetchone())
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(act, current_time=exec_epoch + 300)
        self.assertFalse(is_exp)
        self.assertEqual(rem, 1500)
        self.assertTrue(exp_iso.endswith("Z"), f"Expected UTC Z suffix, got {exp_iso}")
        self.assertNotIn("+00:00Z", exp_iso)

        # Query GET /api/soc/response-actions and verify fields
        r_actions = self.client.get("/api/soc/response-actions", headers=analyst_h)
        self.assertEqual(r_actions.status_code, 200)
        acts = r_actions.get_json()["actions"]
        matching = next(a for a in acts if a["action_id"] == aid)
        self.assertTrue(matching["is_temporary"])
        self.assertIsNotNone(matching["expires_at"])
        self.assertTrue(matching["expires_at"].endswith("Z"))
        self.assertEqual(matching["enforcement_type"], "REAL")

        # Query GET /api/soc/temporary-controls
        r_temp = self.client.get("/api/soc/temporary-controls", headers=analyst_h)
        self.assertEqual(r_temp.status_code, 200)
        temp_data = r_temp.get_json()
        self.assertGreaterEqual(temp_data["active_count"], 1)
        active_match = next(a for a in temp_data["active_controls"] if a["action_id"] == aid)
        self.assertEqual(active_match["target_ip"], target_ip)

    # -------------------------------------------------------------------------
    # 39. Timestamp Parsing and Safe Fallbacks
    # -------------------------------------------------------------------------
    def test_39_timestamp_parsing_and_safe_fallbacks(self):
        """Test parse_iso_ts and compute_action_expiry safely handle missing, invalid, and timezone-qualified timestamps."""
        # Standard UTC with Z
        t_z = soc_backend.parse_iso_ts("2026-10-22T02:00:00Z")
        self.assertIsInstance(t_z, float)

        # Standard with +00:00 offset
        t_plus = soc_backend.parse_iso_ts("2026-10-22T02:00:00+00:00")
        self.assertEqual(t_z, t_plus)

        # Timezone with non-UTC offset (+05:30)
        t_ist = soc_backend.parse_iso_ts("2026-10-22T07:30:00+05:30")
        self.assertEqual(t_z, t_ist)

        # Space-separated format
        t_space = soc_backend.parse_iso_ts("2026-10-22 02:00:00")
        self.assertIsInstance(t_space, float)

        # Missing or empty timestamp falls back safely without raising
        t_none = soc_backend.parse_iso_ts(None)
        self.assertIsInstance(t_none, float)

        t_empty = soc_backend.parse_iso_ts("")
        self.assertIsInstance(t_empty, float)

        # Malformed or invalid string falls back safely without raising
        t_invalid = soc_backend.parse_iso_ts("CORRUPTED_TIMESTAMP_VALUE")
        self.assertIsInstance(t_invalid, float)

        # compute_action_expiry on malformed or missing timestamps never raises exception
        act_corrupt = {
            "action_id": 999,
            "timeout_seconds": "invalid_number",
            "executed_at": "bad_date",
            "status": "EXECUTED"
        }
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(act_corrupt)
        self.assertFalse(is_exp)
        self.assertIsNone(rem)
        self.assertIsNone(exp_iso)

    # -------------------------------------------------------------------------
    # 40. Expired Temporary Controls & MITRE ATT&CK Exclusion
    # -------------------------------------------------------------------------
    def test_40_expired_temporary_controls_and_mitre_exclusion(self):
        """Test temporary controls transition to EXPIRED when elapsed and are excluded from verified mitigations."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "198.51.100.82"

        # Ingest attack and verify containment
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "SQL_INJECTION", "severity": "high"
        })
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": target_ip, "timeout_seconds": 600
        })
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        # Verify containment with authentic host nftables proof
        r_v = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ type ipv4_addr; elements = {{ {target_ip} }} }} }}"
        })
        self.assertEqual(r_v.get_json()["status"], "VERIFIED")

        # MITRE matrix reflects 1 verified mitigation
        r_m1 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r_m1.get_json()["mitigated_techniques"], 1)

        # Fast forward time past 600s timeout by backdating executed_at by 1200 seconds
        past_ts = "2025-01-01T00:00:00Z"
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET executed_at = ? WHERE action_id = ?", (past_ts, aid))

        # Requesting temporary controls triggers check_and_update_expired_controls
        r_temp = self.client.get("/api/soc/temporary-controls", headers=analyst_h)
        self.assertEqual(r_temp.status_code, 200)
        t_data = r_temp.get_json()
        expired_aids = [a["action_id"] for a in t_data["expired_controls"]]
        self.assertIn(aid, expired_aids)

        # Verify action status in DB is EXPIRED
        with db(self.test_db_path) as c:
            act_db = dict(c.execute("SELECT status FROM response_actions WHERE action_id = ?", (aid,)).fetchone() or {})
        self.assertEqual(act_db.get("status"), "EXPIRED")
        # Expired actions are excluded from active temporary controls count
        r_actions = self.client.get("/api/soc/response-actions", headers=analyst_h)
        self.assertEqual(r_actions.get_json()["active_temporary_controls_count"], 0)

        # MITRE matrix must EXCLUDE expired actions from verified mitigations!
        r_m2 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r_m2.get_json()["mitigated_techniques"], 0)

    # -------------------------------------------------------------------------
    # 41. Dry-Run Verification Rejection and Strict Firewall Proof
    # -------------------------------------------------------------------------
    def test_41_dry_run_verification_rejection_and_strict_nftables_proof(self):
        """Test dry-run actions cannot be marked verified, and arbitrary text or non-blocking rules are rejected."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "198.51.100.83"

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "PORT_SCAN", "severity": "medium"
        })
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={"target_ip": target_ip})
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)

        # 1. Action executed with DRY_RUN status
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET status = 'DRY_RUN', message = 'Simulated block by SOAR' WHERE action_id = ?", (aid,))

        # Verify must REJECT dry-run actions even if authentic-looking syntax is provided
        r_dry_exec = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ elements = {{ {target_ip} }} }} }}"
        })
        self.assertEqual(r_dry_exec.status_code, 200)
        self.assertFalse(r_dry_exec.get_json()["verified"])
        self.assertEqual(r_dry_exec.get_json()["status"], "VERIFICATION_FAILED")
        self.assertIn("DRY_RUN simulation mode", r_dry_exec.get_json()["error"])

        # Reset action to EXECUTED for testing invalid evidence rejection
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET status = 'EXECUTED', message = 'Rule added' WHERE action_id = ?", (aid,))

        # 2. Reject arbitrary text without firewall syntax
        r_arbitrary = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"Target {target_ip} is definitely blocked because we saw 0 packets in logs."
        })
        self.assertEqual(r_arbitrary.status_code, 200)
        self.assertFalse(r_arbitrary.get_json()["verified"])
        self.assertIn("arbitrary text without valid firewall", r_arbitrary.get_json()["error"])

        # 3. Reject non-blocking rules (e.g. accept without drop or set blocked_ips)
        r_accept = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ chain input {{ ip saddr {target_ip} accept }} }}"
        })
        self.assertEqual(r_accept.status_code, 200)
        self.assertFalse(r_accept.get_json()["verified"])
        self.assertIn("does not demonstrate an active drop/reject", r_accept.get_json()["error"])

        # 4. Reject dry-run note in evidence
        r_ev_dry = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"[DRY_RUN] table inet filter {{ set blocked_ips {{ elements = {{ {target_ip} }} }} }}"
        })
        self.assertEqual(r_ev_dry.status_code, 200)
        self.assertFalse(r_ev_dry.get_json()["verified"])
        self.assertIn("DRY_RUN simulation mode", r_ev_dry.get_json()["error"])

        # 5. Accept genuine containment proof
        r_valid = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ type ipv4_addr; elements = {{ {target_ip} }} }} }}"
        })
        self.assertEqual(r_valid.status_code, 200)
        self.assertTrue(r_valid.get_json()["verified"])
        self.assertEqual(r_valid.get_json()["status"], "VERIFIED")

    # -------------------------------------------------------------------------
    # 42. Preservation of Action ACT-4 in VERIFICATION_PENDING Status
    # -------------------------------------------------------------------------
    def test_42_preserve_act4_verification_pending_status(self):
        """Test Action ACT-4 for INC-4 is preserved in VERIFICATION_PENDING with unverified evidence without expiring."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        target_ip = "192.168.31.98"

        with db(self.test_db_path) as c:
            # Seed Incident INC-4
            c.execute("""
                INSERT INTO incidents (incident_id, title, status, severity, source_ip, signature, defense_status, created_at, updated_at)
                VALUES (4, 'Brute Force detected from 192.168.31.98', 'CONTAINMENT_PENDING_APPROVAL', 'medium', ?, 'BRUTE_FORCE', 'Verification Pending', '2026-10-22T00:13:23+00:00', '2026-10-22T00:13:23+00:00')
            """, (target_ip,))
            # Seed Action ACT-4 in VERIFICATION_PENDING with timeout 1800s and unverified evidence
            c.execute("""
                INSERT INTO response_actions (action_id, incident_id, target_ip, action_type, status, triggered_by, timeout_seconds, created_at, executed_at, verification_evidence)
                VALUES (4, 4, ?, 'BLOCK_IP', 'VERIFICATION_PENDING', 'SOC_ANALYST', 1800, '2026-10-22T00:13:23+00:00', NULL, NULL)
            """, (target_ip,))

        # Run expiry check (simulate passage of time)
        with db(self.test_db_path) as c:
            soc_backend.check_and_update_expired_controls(c)

        # ACT-4 must NOT be transitioned to EXPIRED; its status must be preserved
        with db(self.test_db_path) as c:
            act = dict(c.execute("SELECT * FROM response_actions WHERE action_id = 4").fetchone())
            inc = dict(c.execute("SELECT * FROM incidents WHERE incident_id = 4").fetchone())

        self.assertEqual(act["status"], "VERIFICATION_PENDING")
        self.assertIsNone(act["verification_evidence"])
        self.assertEqual(inc["defense_status"], "Verification Pending")

        # GET /api/soc/response-actions returns defense_status 'Verification Pending' and unverified evidence
        r_act = self.client.get("/api/soc/response-actions", headers=analyst_h)
        self.assertEqual(r_act.status_code, 200)
        acts = r_act.get_json()["actions"]
        act4 = next(a for a in acts if a["action_id"] == 4)
        self.assertEqual(act4["defense_status"], "Verification Pending")
        self.assertIsNone(act4["evidence_parsed"])
        self.assertFalse(act4["is_expired"])

        # GET /api/soc/temporary-controls lists ACT-4 in active controls with 'Verification Pending'
        r_temp = self.client.get("/api/soc/temporary-controls", headers=analyst_h)
        self.assertEqual(r_temp.status_code, 200)
        temp_data = r_temp.get_json()
        active_aids = [a["action_id"] for a in temp_data["active_controls"]]
        self.assertIn(4, active_aids)
        temp_act4 = next(a for a in temp_data["active_controls"] if a["action_id"] == 4)
        self.assertEqual(temp_act4["defense_status"], "Verification Pending")


class TestPurpleTeamResilienceAndMitreMatrix(TestDefensiveSocBackend):
    """
    Dedicated End-to-End Regression Test Suite for Purple Team Resilience Index,
    MITRE ATT&CK Matrix derivation, and Response Action Verification Workflow.
    Covers all 13 required scenarios from Section 9.
    """

    def test_01_no_detected_techniques_resilience_is_na(self):
        """Scenario 1: No detected techniques returns resilience_index as None (N/A) with 0 detected."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsNone(data["resilience_index"])
        self.assertEqual(data["detected_techniques"], 0)
        self.assertEqual(data["mitigated_techniques"], 0)
        # All matrix techniques should be UNTESTED
        for item in data["matrix"]:
            self.assertEqual(item["state"], "UNTESTED")
            self.assertEqual(item["alert_count"], 0)
            self.assertEqual(item["mitigated_count"], 0)

    def test_02_detected_techniques_with_no_verified_mitigation_is_zero(self):
        """Scenario 2: Detected techniques with no verified mitigation yields 0.0% resilience."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        # Ingest alerts for 2 different techniques: PORT_SCAN (T1046) and SQL_INJECTION (T1190)
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.1", "signature": "PORT_SCAN", "severity": "medium"
        })
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.2", "signature": "SQL_INJECTION", "severity": "high"
        })

        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["detected_techniques"], 2)
        self.assertEqual(data["mitigated_techniques"], 0)
        self.assertEqual(data["resilience_index"], 0.0)

        # Both detected techniques must be DETECTED (amber), not MITIGATED
        states = {item["technique_id"]: item["state"] for item in data["matrix"]}
        self.assertEqual(states["T1046"], "DETECTED")
        self.assertEqual(states["T1190"], "DETECTED")

    def test_03_one_of_several_detected_techniques_verified(self):
        """Scenario 3: 1 of 2 detected techniques verified yields 50.0% resilience index."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.10", "signature": "PORT_SCAN", "severity": "medium"
        })
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.20", "signature": "SQL_INJECTION", "severity": "high"
        })

        # Get actual incident_id created by event
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'PORT_SCAN'").fetchone())
            inc_id = inc["incident_id"]

        # Queue block action for PORT_SCAN
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": "198.51.100.10", "incident_id": inc_id, "timeout_seconds": 1800
        })
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        # Verify with authentic nftables evidence
        nft_proof = "table inet filter { set blocked_ips { type ipv4_addr; elements = { 198.51.100.10 } } }"
        r_v = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={"evidence": nft_proof})
        self.assertTrue(r_v.get_json()["verified"])

        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        data = res.get_json()
        self.assertEqual(data["detected_techniques"], 2)
        self.assertEqual(data["mitigated_techniques"], 1)
        self.assertEqual(data["resilience_index"], 50.0)

        tech_map = {item["technique_id"]: item for item in data["matrix"]}
        self.assertEqual(tech_map["T1046"]["state"], "MITIGATED")
        self.assertEqual(tech_map["T1046"]["defense_status"], "Verified")
        self.assertEqual(tech_map["T1190"]["state"], "DETECTED")

    def test_04_duplicate_alerts_and_multiple_actions_do_not_inflate_index(self):
        """Scenario 4: Duplicate alerts & multiple actions for the same technique do not inflate percentage."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        # 5 duplicate alerts for PORT_SCAN (T1046) from IP 1
        for _ in range(5):
            self.client.post("/api/events", headers=agent_h, json={
                "source_ip": "198.51.100.11", "signature": "PORT_SCAN", "severity": "medium"
            })
        # 3 duplicate alerts for PORT_SCAN (T1046) from IP 2
        for _ in range(3):
            self.client.post("/api/events", headers=agent_h, json={
                "source_ip": "198.51.100.12", "signature": "PORT_SCAN", "severity": "medium"
            })

        # Retrieve actual incident_id created
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'PORT_SCAN'").fetchone())
            inc_id = inc["incident_id"]

        # 2 verified actions for PORT_SCAN (for IP 1 and IP 2)
        for ip in ["198.51.100.11", "198.51.100.12"]:
            r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={"target_ip": ip, "incident_id": inc_id})
            aid = r_b.get_json()["action_id"]
            self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
            self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})
            self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
                "evidence": f"table inet filter {{ set blocked_ips {{ type ipv4_addr; elements = {{ {ip} }} }} }}"
            })

        # Ingest 1 alert for SQL_INJECTION (T1190)
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.50", "signature": "SQL_INJECTION", "severity": "high"
        })

        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        data = res.get_json()

        # Denominator: distinct techniques = 2 (T1046, T1190)
        self.assertEqual(data["detected_techniques"], 2)
        # Numerator: distinct mitigated techniques = 1 (T1046)
        self.assertEqual(data["mitigated_techniques"], 1)
        # Exactly 50.0% (1/2), NOT 2/2 or 2/9
        self.assertEqual(data["resilience_index"], 50.0)

    def test_05_execution_without_verification_does_not_turn_technique_green(self):
        """Scenario 5: Execution without verification leaves technique as DETECTED (amber)."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.33", "signature": "COMMAND_INJECTION", "severity": "critical"
        })
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'COMMAND_INJECTION'").fetchone())
            inc_id = inc["incident_id"]

        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={"target_ip": "198.51.100.33", "incident_id": inc_id})
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        # Agent executed action, but no verification proof submitted
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        data = res.get_json()
        self.assertEqual(data["mitigated_techniques"], 0)
        self.assertEqual(data["resilience_index"], 0.0)

        tech = next(t for t in data["matrix"] if t["signature"] == "COMMAND_INJECTION")
        self.assertEqual(tech["state"], "DETECTED")
        self.assertEqual(tech["defense_status"], "Mitigation Applied")
        self.assertEqual(tech["mitigated_count"], 0)

    def test_06_dry_run_evidence_cannot_qualify_as_real_host_containment(self):
        """Scenario 6: Dry-run evidence cannot qualify as real host-firewall containment."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "192.168.31.98", "signature": "BRUTE_FORCE_AUTH", "severity": "medium"
        })
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'BRUTE_FORCE_AUTH'").fetchone())
            inc_id = inc["incident_id"]

        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={"target_ip": "192.168.31.98", "incident_id": inc_id})
        aid = r_b.get_json()["action_id"]

        # Mark action DRY_RUN
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET status = 'DRY_RUN', message = 'Simulated block by SOAR' WHERE action_id = ?", (aid,))

        # Attempt verification with dry-run evidence
        r_v = self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": "[DRY_RUN] table inet filter { set blocked_ips { elements = { 192.168.31.98 } } }"
        })
        self.assertFalse(r_v.get_json()["verified"])
        self.assertEqual(r_v.get_json()["status"], "VERIFICATION_FAILED")

        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        data = res.get_json()
        tech = next(t for t in data["matrix"] if t["technique_id"] == "T1110")
        self.assertEqual(tech["state"], "DETECTED")
        self.assertEqual(data["mitigated_techniques"], 0)
        self.assertEqual(data["resilience_index"], 0.0)

    def test_07_verified_mitigation_updates_only_correctly_linked_technique(self):
        """Scenario 7: Verified action for one technique does not turn unrelated techniques green."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        shared_ip = "198.51.100.77"

        # Attacker uses shared_ip for both PORT_SCAN (T1046) and SQL_INJECTION (T1190)
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": shared_ip, "signature": "PORT_SCAN", "severity": "medium"
        })
        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": shared_ip, "signature": "SQL_INJECTION", "severity": "high"
        })

        # Find incident IDs
        with db(self.test_db_path) as c:
            inc1 = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'PORT_SCAN'").fetchone())
            inc2 = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'SQL_INJECTION'").fetchone())

        # Block IP specifically linked to Incident 1 (PORT_SCAN)
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": shared_ip, "incident_id": inc1["incident_id"]
        })
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        # Verify action
        self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ type ipv4_addr; elements = {{ {shared_ip} }} }} }}"
        })

        # Check MITRE matrix
        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        data = res.get_json()
        tech_map = {t["technique_id"]: t for t in data["matrix"]}

        # PORT_SCAN (T1046) must be MITIGATED
        self.assertEqual(tech_map["T1046"]["state"], "MITIGATED")
        # SQL_INJECTION (T1190) must REMAIN DETECTED even though source_ip is identical!
        self.assertEqual(tech_map["T1190"]["state"], "DETECTED")
        self.assertEqual(tech_map["T1190"]["mitigated_count"], 0)

        self.assertEqual(data["detected_techniques"], 2)
        self.assertEqual(data["mitigated_techniques"], 1)
        self.assertEqual(data["resilience_index"], 50.0)

    def test_08_invalid_expired_failed_rolled_back_mitigation_not_active(self):
        """Scenario 8: Expired, failed, or rolled-back mitigations drop technique back to DETECTED."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "198.51.100.66"

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "PORT_SCAN", "severity": "medium"
        })
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'PORT_SCAN'").fetchone())
            inc_id = inc["incident_id"]

        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={
            "target_ip": target_ip, "incident_id": inc_id, "timeout_seconds": 300
        })
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})

        # Verified
        self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ type ipv4_addr; elements = {{ {target_ip} }} }} }}"
        })
        r_m1 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r_m1.get_json()["mitigated_techniques"], 1)

        # 8a: Expire action
        past_ts = "2024-01-01T00:00:00Z"
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET executed_at = ? WHERE action_id = ?", (past_ts, aid))
            soc_backend.check_and_update_expired_controls(c)

        r_m2 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r_m2.get_json()["mitigated_techniques"], 0)
        self.assertEqual(r_m2.get_json()["resilience_index"], 0.0)
        tech_exp = next(t for t in r_m2.get_json()["matrix"] if t["technique_id"] == "T1046")
        self.assertEqual(tech_exp["state"], "DETECTED")
        self.assertEqual(tech_exp["defense_status"], "Expired")

        # 8b: Verification Failed
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET status = 'VERIFICATION_FAILED' WHERE action_id = ?", (aid,))
        r_m3 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r_m3.get_json()["mitigated_techniques"], 0)
        tech_fail = next(t for t in r_m3.get_json()["matrix"] if t["technique_id"] == "T1046")
        self.assertEqual(tech_fail["state"], "DETECTED")

        # 8c: Rolled Back / Cancelled
        with db(self.test_db_path) as c:
            c.execute("UPDATE response_actions SET status = 'CANCELLED' WHERE action_id = ?", (aid,))
        r_m4 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r_m4.get_json()["mitigated_techniques"], 0)
        tech_rb = next(t for t in r_m4.get_json()["matrix"] if t["technique_id"] == "T1046")
        self.assertEqual(tech_rb["state"], "DETECTED")

    def test_09_incident_closure_alone_does_not_turn_technique_green(self):
        """Scenario 9: Incident workflow closure alone does not mark MITRE mitigation as verified."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": "198.51.100.88", "signature": "PATH_TRAVERSAL", "severity": "high"
        })
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'PATH_TRAVERSAL'").fetchone())
            inc_id = inc["incident_id"]

        # Transition incident directly to CLOSED with rationale
        r_c = self.client.post(f"/api/soc/incidents/{inc_id}/status", headers=analyst_h, json={
            "status": "CLOSED", "rationale": "Closed as false positive after review."
        })
        self.assertEqual(r_c.status_code, 200)

        # Technique must remain DETECTED (amber), NOT MITIGATED (green)
        res = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        data = res.get_json()
        self.assertEqual(data["mitigated_techniques"], 0)
        self.assertEqual(data["resilience_index"], 0.0)

        tech = next(t for t in data["matrix"] if t["signature"] == "PATH_TRAVERSAL")
        self.assertEqual(tech["state"], "DETECTED")
        self.assertEqual(tech["mitigated_count"], 0)

    def test_10_verification_updates_mitre_api_immediately(self):
        """Scenario 10: Live refresh immediately reflects verified action without restarting server."""
        analyst_h = {"Authorization": f"Bearer {TEST_ANALYST_TOKEN}"}
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        target_ip = "198.51.100.123"

        self.client.post("/api/events", headers=agent_h, json={
            "source_ip": target_ip, "signature": "DIR_FUZZ", "severity": "medium"
        })
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT incident_id FROM incidents WHERE signature = 'DIR_FUZZ'").fetchone())
            inc_id = inc["incident_id"]

        # Check before action
        r1 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r1.get_json()["mitigated_techniques"], 0)
        self.assertEqual(r1.get_json()["resilience_index"], 0.0)

        # Queue, approve, execute, verify
        r_b = self.client.post("/api/soc/mitigate/block", headers=analyst_h, json={"target_ip": target_ip, "incident_id": inc_id})
        aid = r_b.get_json()["action_id"]
        self.client.post(f"/api/soc/response-actions/{aid}/approve", headers=analyst_h)
        self.client.post("/api/agent/action-status", headers=agent_h, json={"action_id": aid, "status": "EXECUTED"})
        self.client.post(f"/api/soc/response-actions/{aid}/verify", headers=analyst_h, json={
            "evidence": f"table inet filter {{ set blocked_ips {{ type ipv4_addr; elements = {{ {target_ip} }} }} }}"
        })

        # Immediate GET /api/soc/mitre-matrix reflects the change immediately
        r2 = self.client.get("/api/soc/mitre-matrix", headers=analyst_h)
        self.assertEqual(r2.get_json()["mitigated_techniques"], 1)
        self.assertEqual(r2.get_json()["resilience_index"], 100.0)
        tech = next(t for t in r2.get_json()["matrix"] if t["signature"] == "DIR_FUZZ")
        self.assertEqual(tech["state"], "MITIGATED")

    def test_11_countdown_behavior_for_valid_invalid_missing_and_expired(self):
        """Scenario 11: Countdown behavior handles valid, invalid, missing, and expired timestamps."""
        # 11a: Valid future action
        future_act = {
            "action_id": 101, "status": "VERIFIED", "timeout_seconds": 1800,
            "executed_at": "2099-01-01T00:00:00Z"
        }
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(future_act)
        self.assertFalse(is_exp)
        self.assertGreater(rem, 0)
        self.assertTrue(exp_iso.endswith("Z"))

        # 11b: Expired action
        past_act = {
            "action_id": 102, "status": "VERIFIED", "timeout_seconds": 60,
            "executed_at": "2020-01-01T00:00:00Z"
        }
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(past_act)
        self.assertTrue(is_exp)
        self.assertEqual(rem, 0)

        # 11c: Missing executed_at (e.g. pending execution or verification)
        missing_act = {
            "action_id": 103, "status": "VERIFICATION_PENDING", "timeout_seconds": 1800,
            "executed_at": None, "created_at": "2026-10-22T00:00:00Z"
        }
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(missing_act)
        self.assertFalse(is_exp)
        self.assertEqual(rem, 1800)

        # 11d: Invalid format executed_at with valid timeout
        invalid_act = {
            "action_id": 104, "status": "VERIFIED", "timeout_seconds": 600,
            "executed_at": "not-a-timestamp"
        }
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(invalid_act)
        self.assertFalse(is_exp)
        self.assertGreater(rem, 0)
        self.assertIsNotNone(exp_iso)

        # 11e: Invalid timeout_seconds
        corrupt_act = {
            "action_id": 105, "status": "VERIFIED", "timeout_seconds": "not-a-number",
            "executed_at": "2026-10-22T00:00:00Z"
        }
        is_exp, rem, exp_iso = soc_backend.compute_action_expiry(corrupt_act)
        self.assertFalse(is_exp)
        self.assertIsNone(rem)
        self.assertIsNone(exp_iso)

    def test_12_database_migration_preserves_records(self):
        """Scenario 12: Database migration preserves existing incident and response-action records."""
        # Insert known incident and response action
        with db(self.test_db_path) as c:
            c.execute("""
                INSERT INTO incidents (incident_id, title, status, severity, source_ip, signature, defense_status, created_at, updated_at)
                VALUES (999, 'Test Migration Preservation', 'TRIAGE', 'high', '198.51.100.99', 'PORT_SCAN', 'Detected', '2026-10-22T00:00:00Z', '2026-10-22T00:00:00Z')
            """)
            c.execute("""
                INSERT INTO response_actions (action_id, incident_id, target_ip, action_type, status, triggered_by, timeout_seconds, created_at)
                VALUES (999, 999, '198.51.100.99', 'BLOCK_IP', 'PENDING', 'SOC_ANALYST', 1800, '2026-10-22T00:00:00Z')
            """)

        # Re-run init_db migration
        soc_backend.init_db(self.test_db_path)

        # Verify records are preserved
        with db(self.test_db_path) as c:
            inc = dict(c.execute("SELECT * FROM incidents WHERE incident_id = 999").fetchone())
            act = dict(c.execute("SELECT * FROM response_actions WHERE action_id = 999").fetchone())

        self.assertEqual(inc["title"], "Test Migration Preservation")
        self.assertEqual(inc["status"], "TRIAGE")
        self.assertEqual(act["target_ip"], "198.51.100.99")
        self.assertEqual(act["status"], "PENDING")

    def test_13_unauthorized_users_cannot_approve_or_verify(self):
        """Scenario 13: Unauthorized users cannot approve or verify response actions."""
        # 1. No token provided -> 401 Unauthorized
        r_unauth_app = self.client.post("/api/soc/response-actions/1/approve")
        self.assertEqual(r_unauth_app.status_code, 401)

        r_unauth_ver = self.client.post("/api/soc/response-actions/1/verify", json={"evidence": "test"})
        self.assertEqual(r_unauth_ver.status_code, 401)

        r_unauth_status = self.client.post("/api/soc/incidents/1/status", json={"status": "CLOSED"})
        self.assertEqual(r_unauth_status.status_code, 401)

        # 2. Agent token (valid agent token, but not analyst token) -> 401 Unauthorized
        agent_h = {"Authorization": f"Bearer {TEST_AGENT_TOKEN}"}
        r_agent_app = self.client.post("/api/soc/response-actions/1/approve", headers=agent_h)
        self.assertEqual(r_agent_app.status_code, 401)

        r_agent_ver = self.client.post("/api/soc/response-actions/1/verify", headers=agent_h, json={"evidence": "test"})
        self.assertEqual(r_agent_ver.status_code, 401)


if __name__ == "__main__":
    unittest.main()


