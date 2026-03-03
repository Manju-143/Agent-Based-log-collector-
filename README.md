## Agent-Based Secure Cryptographic Logging System (PKSL)

### Overview

PKSL is a secure, agent-based cryptographic logging framework designed to provide tamper-evident, encrypted, and authenticated log collection in zero-trust environments. The system demonstrates a defence-in-depth approach by combining modern cryptographic mechanisms across identity, transport, storage, and verification layers.

This prototype was developed to demonstrate a secure logging architecture suitable for Security Operations Centres (SOC), SIEM platforms, cloud-native applications, and distributed infrastructure. The focus is on protecting log integrity from generation to long-term storage while supporting secure monitoring and forensic analysis.

---

### Key Security Objectives

The system aims to:

1. Ensure log integrity and detect tampering.
2. Protect confidentiality using authenticated encryption.
3. Prevent replay and cross-session attacks.
4. Establish secure communication and identity validation.
5. Support secure indexing without trusting the indexing layer.
6. Demonstrate practical and real-world cryptographic system design.

---

### Security Architecture

PKSL integrates multiple cryptographic controls:

#### Identity and Trust

* Public Key Infrastructure (PKI)
* ECDSA P-256 Certificate Authority
* Agent certificate issuance
* Certificate Revocation List (CRL) validation

#### Secure Transport

* Noise Protocol Framework (Noise_XX pattern)
* Mutual authentication using static keys
* Forward secrecy and session binding

#### Integrity and Tamper Detection

* SHA-256 hash chaining
* Append-only log storage
* Independent integrity verification tool

#### Authentication and Non-Repudiation

* Ed25519 digital signatures

---

### Project Structure

```
agent/
server/
pksl/
tools/
keys/
pki/
data/
docker-compose.opensearch.yml
requirements.txt
README.md
```

---

### Installation and Setup

#### Step 1: Clone the repository

```
git clone <your_repo_url>
cd project
```

#### Step 2: Create a virtual environment

```
python -m venv .venv
.venv\Scripts\activate
```

#### Step 3: Install dependencies

```
pip install -r requirements.txt
```

---

### Cryptographic Key and PKI Setup

The system includes an automated wizard for key and certificate generation.

Run:

```
python tools\pki_wizard.py
```

This tool supports:

* AES-256 key generation
* Certificate Authority creation
* Agent certificate issuance
* Ed25519 signing key generation
* Noise static key generation
* Certificate revocation
* CRL updates

Recommended workflow:

1. Create the Certificate Authority.
2. Generate agent signing keys.
3. Generate Noise static keys.
4. Issue agent certificates.
5. Generate AES encryption keys.

---

### Environment Configuration

Set encryption key:

```
$env:PKSL_AES_KEY="your_base64_key"
```

Set agent certificate:

```
$env:PKSL_AGENT_CERT="pki/issued/agent-01_cert.pem"
```

---

### Running the System

#### Start the server

```
.venv\Scripts\activate
python -m server.server
```

#### Start the agent (new terminal)

```
.venv\Scripts\activate
python -m agent.agent
```

The agent will:

* Establish a secure Noise session
* Encrypt and sign log records
* Transmit logs continuously
* Maintain persistent state

---

### Verifying Log Integrity

Stop the agent and run:

```
python -m tools.verify_logfile
```

The verification tool checks:

* Hash chain integrity
* Signature correctness
* Replay protection
* Tamper detection

This demonstrates independent forensic validation.

---

### OpenSearch Integration

The system supports secure indexing for monitoring and analytics.

Start OpenSearch:

```
docker compose -f docker-compose.opensearch.yml up -d
```

Access the dashboard:

```
http://localhost:5601
```

Create index pattern:

```
pksl-logs
```

The index is non-authoritative, meaning cryptographic integrity remains enforced locally.

---

### Threat Model and Security Benefits

PKSL mitigates the following risks:

* Log tampering and deletion
* Replay and injection attacks
* Insider manipulation
* Network interception
* Session hijacking
* Certificate compromise
* Data exposure in transit
* Centralised logging trust weaknesses

---

### Demonstration Workflow

A typical demonstration includes:

1. Starting the server and agent.
2. Showing encrypted and signed log transmission.
3. Visualising logs in OpenSearch.
4. Modifying logs manually.
5. Running the verification tool.
6. Demonstrating tamper detection.
7. Revoking certificates and validating denial.

---

### Limitations

This system is a research prototype and includes:

* Single-node deployment
* Simplified certificate lifecycle
* No hardware security module integration
* Limited scalability testing

These provide scope for further research and development.

---

### Future Improvements

* Kubernetes deployment
* Hardware security module integration
* Multi-tenant identity
* Advanced zero-trust architecture
* Secure key rotation
* Distributed consensus storage
* Automated threat detection

---

### Use Cases

* SOC logging pipelines
* Cloud security monitoring
* Compliance and audit logging
* Critical infrastructure protection
* Financial and healthcare environments
* Zero-trust systems

---
## Containerised Deployment (Docker)

### Overview

The Secure Cryptographic Logging System is fully containerised using Docker to ensure portability, reproducibility, and consistent runtime environments. The server and agent components are orchestrated using Docker Compose. Sensitive configuration is injected at runtime via environment variables rather than being embedded in source code or container images.

---

### Prerequisites

- Docker Desktop installed and running  
- Git installed  
- Python (only required for PKI generation using the provided tools)

---

### Environment Configuration

Create a `.env` file in the project root directory (this file must not be committed to version control):
#.env
PKSL_AES_KEY=<base64-encoded-32-byte-key>
OPENSEARCH_INITIAL_ADMIN_PASSWORD=<admin-password>


#To generate a secure 256-bit AES key: python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"

Copy the generated value into `PKSL_AES_KEY`.

---

### PKI Initialisation (One-Time Setup)

If certificate material does not already exist, initialise the PKI using:
#script for key generation
python tools\pki_wizard.py

Recommended steps:

- Create CA (if not already created)  
- Use the "Do ALL for an agent" option to generate:
  - Ed25519 signing keys  
  - Noise static keys  
  - X.509 certificate signed by the CA  

This ensures the agent can authenticate securely with the server.

---

### Build and Run Containers

From the project root directory:

docker compose up --build

This will:

- Build the Docker image  
- Start the PKI server  
- Start the agent  
- Establish secure Noise transport  
- Enforce certificate validation and replay protection  

---

### Stopping the System

To stop all services:
docker compose down
