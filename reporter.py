#!/usr/bin/env python3
import os
import json
import time
import re
import requests
import logging
from datetime import datetime, timedelta
from pathlib import Path

API_KEY       = os.environ.get("ABUSEIPDB_KEY", "")
LOG_PATH      = os.environ.get("HELLPOT_LOG", "/logs/hellpot.log")
COOLDOWN_MIN  = int(os.environ.get("COOLDOWN_MINUTES", "15"))
# AbuseIPDB categories: 14=port scan, 21=web app attack
CATEGORIES    = os.environ.get("ABUSEIPDB_CATEGORIES", "14,21")
DRY_RUN       = os.environ.get("DRY_RUN", "false").lower() == "true"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("reporter")

reported_cache: dict[str, datetime] = {}


def extract_ip(line: str) -> str | None:
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        m = re.search(r'"(?:remote|ip|addr|client)"\s*:\s*"([\d\.]+)(?::\d+)?"', line)
        return m.group(1) if m else None

    for key in ("REMOTE_ADDR", "remote", "ip", "addr", "client", "remote_addr"):
        val = obj.get(key)
        if val and isinstance(val, str):
            ip = val.split(":")[0]
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
    return None


def should_report(ip: str) -> bool:
    last = reported_cache.get(ip)
    if last is None:
        return True
    return datetime.now() - last > timedelta(minutes=COOLDOWN_MIN)


def report_ip(ip: str, comment: str = "") -> bool:
    if DRY_RUN:
        log.info(f"[DRY-RUN] skipping report: {ip}")
        return True

    url = "https://api.abuseipdb.com/api/v2/report"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json",
    }
    payload = {
        "ip": ip,
        "categories": CATEGORIES,
        "comment": comment or f"HellPot HTTP honeypot: unsolicited connection from {ip}",
    }
    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=10)
        if resp.status_code == 200:
            score = resp.json().get("data", {}).get("abuseConfidenceScore", "?")
            log.info(f"reported: {ip} (abuse score: {score})")
            return True
        elif resp.status_code == 422:
            log.debug(f"skipped (duplicate within window): {ip}")
            return True
        elif resp.status_code == 429:
            log.warning("rate limit reached, sleeping 60s")
            time.sleep(60)
            return False
        else:
            log.warning(f"report failed: {ip} -> HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except requests.RequestException as e:
        log.error(f"network error: {ip} -> {e}")
        return False


def tail_log(path: str):
    """Generator that follows a log file like `tail -f`."""
    log.info(f"watching log: {path}")
    while not Path(path).exists():
        log.info(f"waiting for log file: {path}")
        time.sleep(5)

    with open(path, "r") as f:
        f.seek(0, 2)  # start from end; skip existing lines
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                try:
                    if f.tell() > Path(path).stat().st_size:
                        f.seek(0, 2)
                except FileNotFoundError:
                    log.warning("log file removed, waiting for recreation")
                    break
                time.sleep(0.5)


def main():
    if not API_KEY:
        log.error("ABUSEIPDB_KEY environment variable is not set")
        raise SystemExit(1)
    if DRY_RUN:
        log.info("DRY-RUN mode: no reports will be sent")

    log.info(f"cooldown={COOLDOWN_MIN}m categories={CATEGORIES} log={LOG_PATH}")

    while True:
        try:
            for line in tail_log(LOG_PATH):
                ip = extract_ip(line)
                if not ip:
                    continue
                if ip.startswith(("10.", "192.168.", "127.", "172.")):
                    continue
                if not should_report(ip):
                    log.debug(f"cooldown active: {ip}")
                    continue

                log.info(f"reporting: {ip}")
                comment = ""
                try:
                    obj = json.loads(line.strip())
                    path_val = obj.get("path", obj.get("uri", ""))
                    ua = obj.get("user_agent", obj.get("ua", ""))
                    if path_val:
                        comment = f"HellPot HTTP honeypot: accessed {path_val}"
                        if ua:
                            comment += f" UA: {ua[:100]}"
                except Exception:
                    pass

                if report_ip(ip, comment):
                    reported_cache[ip] = datetime.now()

        except FileNotFoundError:
            log.warning(f"log file not found: {LOG_PATH}, retrying")
            time.sleep(5)
        except KeyboardInterrupt:
            log.info("shutting down")
            break
        except Exception as e:
            log.error(f"unexpected error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
