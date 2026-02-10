# SSH Honeypot

## Overview

This project implements a **containerized SSH honeypot** designed to detect, log, and analyze unauthorized access attempts in a controlled environment. The honeypot simulates a realistic Ubuntu OpenSSH server while safely isolating all attacker interactions from real systems.

The purpose of this honeypot is to capture attacker behavior, including credential brute-forcing, post-authentication reconnaissance, and suspicious command execution, without exposing any real infrastructure.

This project was developed as part of **CSCE 413 – Assignment 2**.

---

## Architecture

The honeypot is implemented as a single Docker container using the **Paramiko** Python SSH library. It emulates a functional SSH server and shell environment while logging all attacker activity.

### Key Components

- **Fake SSH Server**
  - Listens for incoming SSH connections
  - Presents a realistic OpenSSH banner
  - Accepts a limited set of common credentials

- **Authentication Handler**
  - Records all login attempts (successful and failed)
  - Tracks usernames and passwords used by attackers

- **Simulated Shell**
  - Responds to common Linux commands (`ls`, `whoami`, `uname`, `pwd`, etc.)
  - Prevents real system access or privilege escalation

- **Logging System**
  - Captures detailed interaction data for analysis

---

## Logging Mechanisms

The honeypot records activity in two formats:

### Human-Readable Logs
- File: `honeypot.log`
- Used for real-time monitoring and debugging
- Includes connection events and authentication attempts

### Structured JSON Logs
- File: `events.jsonl`
- One JSON object per event
- Fields include:
  - Timestamp
  - Source IP and port
  - Authentication attempts
  - Commands executed
  - Session duration
  - Raw input data

This structured format enables efficient post-attack analysis and correlation.

---

## Requirements

- Docker
- Docker Compose
- Python 3
- Paramiko (included in container image)

---

## Deployment

Build and start the honeypot:

```bash
docker-compose up --build honeypot
```

The honeypot exposes an SSH service that can be accessed locally:

```bash
ssh root@localhost -p 2222
```

Attackers may attempt common credentials such as:

```bash
root:toor
admin:admin
user:password
```

## Viewing Logs

View real-time honeypot output:
```bash
docker-compose logs honeypot
```

Inspect stored logs inside the container:
```bash
docker-compose exec honeypot sh -lc "ls -l /app/logs"
docker-compose exec honeypot sh -lc "tail -n 50 /app/logs/events.jsonl"
```

## Improvements and Future Work
* Add SSH key authentication tracking
* Integrate alerting for high-risk commands
* Deploy multiple honeypots with varied configurations
* Forward logs to a centralized SIEM
* Add time-based session expiration