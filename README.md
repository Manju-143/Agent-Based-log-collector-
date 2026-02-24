# PKI Secure Logging (Prototype)

Secure logging pipeline prototype: agent → server → append-only storage.
(Upcoming phases: hash chaining, signatures, encryption, PKI, Noise, Docker/K8s.)

## Run locally (PowerShell)

### Server
```powershell
.venv\Scripts\Activate
$env:PKSL_STORAGE_DIR=".\data"
$env:PKSL_SERVER_HOST="127.0.0.1"
$env:PKSL_SERVER_PORT="9000"
python -m server.server
```

### Agent
```powershell
.venv\Scripts\Activate
$env:PKSL_AGENT_ID="agent-01"
$env:PKSL_TARGET_HOST="127.0.0.1"
$env:PKSL_TARGET_PORT="9000"
python -m agent.agent
```