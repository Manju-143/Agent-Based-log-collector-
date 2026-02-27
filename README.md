Public Key Infrastructure (PKI)

The system supports certificate-based authentication of agents using X.509 certificates. It includes certificate validation and Certificate Revocation List (CRL) functionality, allowing compromised or unauthorized agents to be revoked and blocked.

Integrity and Detection

An append-only storage model is used to preserve log integrity. Tamper detection and verification tools are provided to independently validate stored logs. Any alteration in the log chain is immediately detectable.

Observability

Optional integration with OpenSearch enables log indexing and analytics. This provides SIEM-style visibility and supports monitoring, alerting, and visualization of security events.

## Architecture

The system consists of the following components:

Secure log agents

Central verification server

PKI trust infrastructure

Tamper-evident storage

Optional search and visualization layer

The workflow follows this sequence:
Agents generate logs, encrypt them, digitally sign the records, and transmit them securely to the central server. The server verifies authenticity and integrity, stores the records in an append-only format, and optionally indexes them for analytics.

## Setup
1. Install dependencies
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
2. Generate cryptographic keys
python -m tools.gen_keys
3. Set encryption key
$env:PKSL_AES_KEY="YOUR_BASE64_AES_KEY"
4. Start the server
python -m server.server
5. Run the agent
python -m agent.agent
Verification and Tamper Testing
Tamper detection

To test tamper detection, modify any record in:

## data/verified_logs.jsonl

Then run:

## python -m tools.verify_logfile

The system will identify the modification and report a verification failure.

## Certificate revocation

Revoke an agent certificate and restart the server. The revoked agent will no longer be able to authenticate or transmit logs.

OpenSearch Integration (Optional)

## To enable log analytics:

docker compose up -d

## Dashboards can be accessed at:

http://localhost:5601
Security Objectives

## This system is designed to protect against the following threats:

Log tampering

Replay attacks

Man-in-the-middle interception

Agent impersonation

Unauthorized modification of stored records

## Technologies

Python

Noise Protocol

Ed25519

AES-GCM

SHA-256

PKI and CRL

OpenSearch

## Disclaimer

This project is intended for academic and research purposes only. It demonstrates secure design concepts and is not intended to replace production-grade security solutions without further hardening and validation.

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
