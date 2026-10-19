# Mini Enterprise Defensive SOC starter

- `nftables.conf`: host firewall template; replace SOC IP and test before applying.
- `agent_remediator.py`: constrained nftables block/unblock poller; defaults to dry-run.
- `soc_backend.py`: starter Flask API and SQLite schema.
- `dashboard_component.html/.js/.css`: MITRE matrix UI.
- `sudoers-mini_soc_agent.example`: privilege guidance, intentionally not install-ready.

## Important
This is a starter implementation, not yet integrated with your existing dashboard or agent.
Reconcile the actual event schema, authentication, routes and database migrations before use.
The SOC API binds to localhost by default; use TLS/reverse proxy before remote exposure.
Do not disable TLS verification for a real deployment.

Test firewall syntax first: `sudo nft -c -f nftables.conf`. Ensure console access before
applying default-drop rules remotely. Keep `SOAR_DRY_RUN=true` until action approval,
rollback, and end-to-end verification have been tested.

`EXECUTED` is not independently verified containment. The matrix expects `VERIFIED`, which
must only be recorded after checking the actual CN-Server nftables set.
