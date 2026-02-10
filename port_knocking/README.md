# Port Knocking Service

## Overview

This project implements a **port knocking mechanism** to protect a sensitive SSH service in a containerized environment. The SSH service is hidden by default and only becomes accessible after a client sends a correct sequence of connection attempts (knocks) to predefined ports within a limited time window.

This implementation reduces the exposed attack surface of administrative services and demonstrates how network-layer defenses can mitigate automated scanning and brute-force attacks.

This project was developed as part of **CSCE 413 – Assignment 2**.
---

## Architecture

The system consists of two containerized components:

### Protected SSH Service (`secret_ssh`)
- Runs an SSH server on port **2222**
- Port is blocked by default using firewall rules
- Becomes accessible only after a valid knock sequence

### Port Knocking Gateway (`port_knocking`)
- Monitors incoming connection attempts
- Validates the knock sequence and timing
- Dynamically updates firewall rules to allow SSH access

---

## Requirements

- Docker
- Docker Compose
- Python 3
- Linux-based environment with `iptables`

---

## Deployment

Start the protected SSH service and port knocking gateway:

```bash
docker compose up -d --force-recreate secret_ssh port_knocking
```
Verify that the SSH service is initially inaccessible:

```bash
docker compose exec port_knocking sh -lc "nc -zv secret_ssh 2222 || true"
```

Expected output:
```bash
nc: connect to secret_ssh (172.20.0.20) port 2222 (tcp) failed: Connection timed out
```

Sending the Knock Sequence

Send the correct knock sequence using the knock client:
```bash
docker compose exec port_knocking sh -lc \ "python3 knock_client.py --target secret_ssh --sequence 1234,5678,9012"
```

If the sequence is valid, firewall rules are updated to allow SSH traffic.

Verify access:
```bash
docker compose exec port_knocking sh -lc "nc -zv secret_ssh 2222 || true"
```

Expected output:
```bash
Connection to secret_ssh (172.20.0.20) 2222 port [tcp/*] succeeded!
```

## Security Analysis
Benefits

* SSH service is invisible to port scans
* Prevents automated brute-force attacks
* Reduces exposed administrative attack surface
* Minimizes authentication noise in logs

Limitations
* Knock sequence may be discovered through traffic analysis
* Provides no encryption or authentication by itself
* Static sequences can be reused if compromised