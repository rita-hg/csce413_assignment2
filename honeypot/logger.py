#!/usr/bin/env python3
from __future__ import annotations

"""Logging helpers for the honeypot:
- /app/logs/honeypot.log      (human-readable)
- /app/logs/events.jsonl      (structured JSON lines for analysis)
"""

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

LOG_DIR = "/app/logs"
TEXT_LOG_PATH = os.path.join(LOG_DIR, "honeypot.log")
JSON_LOG_PATH = os.path.join(LOG_DIR, "events.jsonl")


class JsonlLogger:
    def __init__(self, path: str):
        self.path = path

    def write(self, event: Dict[str, Any]) -> None:
        # Ensure timestamp exists even if caller forgets
        event.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        line = json.dumps(event, ensure_ascii=False)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def create_logger(name: str = "honeypot") -> tuple[logging.Logger, JsonlLogger]:
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Avoid duplicate handlers if reloaded
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        file_handler = RotatingFileHandler(
            TEXT_LOG_PATH, maxBytes=2_000_000, backupCount=5
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(logging.INFO)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(fmt)
        stream_handler.setLevel(logging.INFO)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    jsonl = JsonlLogger(JSON_LOG_PATH)
    return logger, jsonl


def alert_if_interesting(logger: logging.Logger, event: Dict[str, Any]) -> None:
    """
    Lightweight “alerting”: raises log level when certain conditions occur.
    """
    et = event.get("event_type", "")
    if et in {"auth_success", "session_open"}:
        logger.warning("ALERT: %s", event)
    if et == "command":
        cmd = (event.get("command") or "").lower()
        suspicious = ["wget ", "curl ", "nc ", "ncat", "bash -i", "python -c", "chmod +x", "scp ", "ssh "]
        if any(s in cmd for s in suspicious):
            logger.warning("ALERT: suspicious command: %s", event)
