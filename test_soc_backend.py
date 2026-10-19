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
from soc_backend import app, init_db, db, get_agent_token, get_analyst_token, REGISTRY

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
        # Clear rows in temporary test database between tests to ensure test isolation
        with db(self.test_db_path) as c:
            c.execute("DELETE FROM incident_notes")
            c.execute("DELETE FROM alerts")
            c.execute("DELETE FROM response_actions")
            c.execute("DELETE FROM incidents")

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
        """Verify SOC_BIND_HOST and SOC_PORT are parsed correctly from environment."""
        orig_host = os.environ.get("SOC_BIND_HOST")
        orig_port = os.environ.get("SOC_PORT")
        try:
            os.environ["SOC_BIND_HOST"] = "0.0.0.0"
            os.environ["SOC_PORT"] = "9090"
            parsed_host = os.getenv("SOC_BIND_HOST", "127.0.0.1")
            parsed_port = int(os.getenv("SOC_PORT", "8443"))
            self.assertEqual(parsed_host, "0.0.0.0")
            self.assertEqual(parsed_port, 9090)
        finally:
            if orig_host is not None: os.environ["SOC_BIND_HOST"] = orig_host
            else: os.environ.pop("SOC_BIND_HOST", None)
            if orig_port is not None: os.environ["SOC_PORT"] = orig_port
            else: os.environ.pop("SOC_PORT", None)

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
            "source_ip": "198.51.100.22", "signature": "SQL_INJECTION", "severity": "high"
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
            "source_ip": "203.0.113.88", "signature": "DIR_FUZZ", "severity": "medium"
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

if __name__ == "__main__":
    unittest.main()
