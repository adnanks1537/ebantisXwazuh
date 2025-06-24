#!/usr/bin/env python3
import sys
import json
import requests
import logging
import os
import time
import signal
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Configure logging to integrations.log
logging.basicConfig(
    filename="/var/ossec/logs/integrations.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
WEBHOOK_URL = "https://wazuhapiv2.onrender.com/wazuh-alerts"  # Updated FastAPI URL
ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
VERIFY_SSL = True
POLL_INTERVAL = 1  # Seconds between file checks
running = True

def signal_handler(sig, frame):
    """Handle SIGTERM and SIGINT for graceful shutdown."""
    global running
    logger.info("Received shutdown signal, stopping service")
    running = False
    sys.exit(0)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(requests.exceptions.RequestException),
    before_sleep=lambda retry_state: logger.warning(f"Retrying alert send: attempt {retry_state.attempt_number}")
)
def send_alert(alert):
    """Send a single alert to the FastAPI endpoint."""
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(
            WEBHOOK_URL,
            json=alert,
            headers=headers,
            timeout=30,
            verify=VERIFY_SSL
        )
        response.raise_for_status()
        logger.info(f"Successfully sent alert: rule_id={alert.get('rule', {}).get('id')}, timestamp={alert.get('timestamp')}, agent_id={alert.get('agent', {}).get('id')}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send alert: {str(e)}, alert={json.dumps(alert)}")
        raise

def process_alerts():
    """Continuously monitor alert file for new alerts."""
    last_position = 0
    while running:
        try:
            if not os.path.exists(ALERT_FILE):
                logger.error(f"Alert file not found: {ALERT_FILE}")
                time.sleep(POLL_INTERVAL)
                continue

            with open(ALERT_FILE, "r") as f:
                f.seek(last_position)
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        if alert.get("rule", {}).get("level", 0) >= 1:  # Filter by level
                            send_alert(alert)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in alert: {line.strip()}, error={str(e)}")
                    except Exception as e:
                        logger.error(f"Error processing alert: {str(e)}, alert={line.strip()}")
                last_position = f.tell()
            time.sleep(POLL_INTERVAL)
        except Exception as e:
            logger.error(f"Error reading alert file: {str(e)}")
            time.sleep(POLL_INTERVAL)

def main():
    """Main function to start the service."""
    try:
        logger.info("Starting custom FastAPI integration service")
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        process_alerts()
        logger.info("Service stopped")
    except Exception as e:
        logger.error(f"Service failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
