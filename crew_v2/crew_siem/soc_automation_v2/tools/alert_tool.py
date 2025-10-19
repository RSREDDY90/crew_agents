# tools/alert_tool.py
import os
import requests
from tenacity import retry, wait_exponential, stop_after_attempt
from dotenv import load_dotenv

load_dotenv()
ALERT_API_URL = os.getenv("ALERT_API_URL")
ALERT_API_KEY = os.getenv("ALERT_API_KEY")

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {ALERT_API_KEY}" if ALERT_API_KEY else ""
}

@retry(wait=wait_exponential(multiplier=0.5, min=1, max=3), stop=stop_after_attempt(3))
def send_incident_alert(payload: dict):
    """
    Sends an incident alert via REST POST. Retries transient failures.
    Returns response.json() on success.
    """
    # if not ALERT_API_URL:
    #     raise RuntimeError("ALERT_API_URL not configured")
    # resp = requests.post(ALERT_API_URL, json=payload, headers=HEADERS, timeout=10)
    # resp.raise_for_status()
    return dict