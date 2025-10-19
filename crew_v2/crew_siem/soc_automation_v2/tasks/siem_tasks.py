# tasks/siem_tasks.py
from crewai import Task
from agents.soc_agents import investigator, correlator, responder, reporter
from tools.clickhouse_tool import query_clickhouse
from tools.alert_tool import send_incident_alert
from tools.milvus_tool import store_incidents_to_milvus
from datetime import datetime, timedelta


import logging
import sys
import os

# Create log directory if it doesn't exist
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "siem_tasks.log")

# At top of siem_tasks.py
logger = logging.getLogger("SIEM_Tasks")
logger.setLevel(logging.INFO)
logger.propagate = False  # Do not pass to root logger

if not logger.handlers:
    # Console handler (optional)
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console_handler.setFormatter(console_formatter)

    # File handler
    file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setFormatter(console_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

logger.info("✅ SIEM Tasks logger initialized, logging to file: %s", LOG_FILE)



def analyze_failed_logins_action(context={}):
    threshold = 5
    window_minutes = 10

    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)

    sql = f"""
    SELECT
      ip,
      tenant_id,
      countIf(event_type = 'failed') AS failed_count,
      min(event_time) as first_seen,
      max(event_time) as last_seen
    FROM siem_login_events
    WHERE event_time >= toDateTime('{window_start.strftime('%Y-%m-%d %H:%M:%S')}')
    GROUP BY ip, tenant_id
    HAVING failed_count >= {threshold}
    ORDER BY failed_count DESC
    LIMIT 100
    """

    rows = query_clickhouse(sql)
    results = []
    for r in rows:
        results.append({
            "ip": r.get("ip"),
            "tenant_id": r.get("tenant_id"),
            "failed_count": int(r.get("failed_count") or 0),
            "first_seen": str(r.get("first_seen")),
            "last_seen": str(r.get("last_seen"))
        })
    return results

import uuid

def correlate_successful_logins_action(failed_ips, context={}):
    incidents = []
    for ip_obj in failed_ips:
        ip = ip_obj["ip"]
        last_seen = ip_obj["last_seen"]

        sql = f"""
        SELECT tenant_id, user_id, ip, event_time, event_type
        FROM siem_login_events
        WHERE ip = '{ip}'
          AND event_time > toDateTime('{last_seen}')
          AND event_time <= toDateTime(date_add('second', 300, toDateTime('{last_seen}')))
          AND event_type = 'success'
        LIMIT 10
        """
        rows = query_clickhouse(sql)
        if rows:
            incident = {
                "incident_id": str(uuid.uuid4()),
                "ip": ip,
                "tenant_id": ip_obj["tenant_id"],
                "failed_count": ip_obj["failed_count"],
                "evidence": [dict(r) for r in rows]
            }
            incidents.append(incident)
    return incidents


# def responder_action(incidents, context={}):
#     results = []
#     for inc in incidents:
#         payload = {
#             "title": "Potential account compromise - brute force followed by success",
#             "ip": inc["ip"],
#             "tenant_id": inc["tenant_id"],
#             "failed_count": inc["failed_count"],
#             "evidence": inc["evidence"],
#             "suggested_action": ["block_ip", "force_password_reset", "notify_owner"]
#         }
#         resp = send_incident_alert(payload)
#         results.append({"payload": payload, "response": resp})
#     return results


def responder_action(incidents, context={}):
    import logging, sys, os

    # Ensure logs folder exists
    LOG_DIR = "logs"
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_FILE = os.path.join(LOG_DIR, "siem_tasks.log")

    # Initialize logger
    logger = logging.getLogger("SIEM_Tasks")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Avoid adding multiple handlers
    if not logger.handlers:
        # Console
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(ch)
        # File
        fh = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)

    # Log start
    logger.info(f"🔄 responder_action: {len(incidents)} incidents")

    results = []
    for inc in incidents:
        payload = {
            "title": "Potential account compromise - brute force followed by success",
            "ip": inc["ip"],
            "tenant_id": inc["tenant_id"],
            "failed_count": inc["failed_count"],
            "evidence": inc["evidence"],
            "suggested_action": ["block_ip", "force_password_reset", "notify_owner"]
        }
        resp = send_incident_alert(payload)
        results.append({"payload": payload, "response": resp})
        logger.info(f"Sent alert for IP: {inc['ip']} tenant: {inc['tenant_id']}")

    stored_count = store_incidents_to_milvus(incidents)
    context["milvus_stored_count"] = stored_count
    logger.info(f"✅ Stored {stored_count} incidents into Milvus")

    return results

# def reporter_action(incidents, responder_results, context={}):
#     if not incidents:
#         return "# SIEM Report\n\nNo incidents detected."

#     lines = ["# SIEM Incident Report\n"]
#     for i, inc in enumerate(incidents, start=1):
#         lines.append(f"## Incident {i}: IP {inc['ip']}")
#         lines.append(f"- Tenant: {inc['tenant_id']}")
#         lines.append(f"- Failed attempts: {inc['failed_count']}")
#         lines.append("- Evidence:")
#         for e in inc["evidence"]:
#             lines.append(f"  - {e.get('event_time')} user={e.get('user_id')} event={e.get('event_type')}")
#         if i-1 < len(responder_results):
#             lines.append(f"- Alert API response: {responder_results[i-1].get('response')}")
#         lines.append("")
#     return "\n".join(lines)

def reporter_action(incidents, responder_results, context={}):
    if not incidents:
        return "# SIEM Report\n\nNo incidents detected."

    lines = ["# SIEM Incident Report\n"]
    for i, inc in enumerate(incidents, start=1):
        lines.append(f"## Incident {i}: IP {inc['ip']}")
        lines.append(f"- Tenant: {inc['tenant_id']}")
        lines.append(f"- Failed attempts: {inc['failed_count']}")
        lines.append("- Evidence:")
        for e in inc["evidence"]:
            lines.append(f"  - {e.get('event_time')} user={e.get('user_id')} event={e.get('event_type')}")
        if i-1 < len(responder_results):
            lines.append(f"- Alert API response: {responder_results[i-1].get('response')}")
        lines.append("")
    lines.append(f"\n✅ {context.get('milvus_stored_count', 0)} incidents stored in Milvus.")
    return "\n".join(lines)


# --- CrewAI Task Definitions ---

analyze_failed_logins = Task(
    name="AnalyzeFailedLogins",
    description="Find IPs with > threshold failed login attempts within a short time window.",
    expected_output="A list of IPs with their failed login counts and timestamps.",
    function=analyze_failed_logins_action,
    agent=investigator
)

correlate_successful_logins = Task(
    name="CorrelateSuccess",
    description="Correlate failed login IPs with successful logins within 5 minutes.",
    expected_output="A list of potential incidents where a successful login followed multiple failures.",
    function=correlate_successful_logins_action,
    agent=correlator
)

incident_response_task = Task(
    name="IncidentResponder",
    description="Trigger incident alerts via REST API for confirmed suspicious activities.",
    expected_output="A list of alert responses confirming that incident notifications were sent.",
    function=responder_action,
    agent=responder
)

generate_report_task = Task(
    name="GenerateReport",
    description="Create a markdown summary report for the SOC team detailing incidents and responses.",
    expected_output="A markdown report summarizing detected incidents, evidence, and response status.",
    function=reporter_action,
    agent=reporter
)