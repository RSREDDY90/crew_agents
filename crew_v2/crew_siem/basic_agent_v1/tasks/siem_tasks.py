from crewai import Task
from agents.soc_agents import investigator, correlator, responder, reporter

analyze_failed_logins = Task(
    description="Query failed login events from ClickHouse and find repeated failures per IP.",
    expected_output="A list of IPs with number of failed login attempts > 5 within 10 minutes.",
    agent=investigator
)

correlate_successful_logins = Task(
    description="Check if these IPs had a successful login within 5 minutes of failed attempts.",
    expected_output="IPs that transitioned from failed to successful login — potential compromise.",
    agent=correlator
)

incident_response_task = Task(
    description="Generate a recommended action plan — block IP, reset password, or notify admin.",
    expected_output="Incident response JSON containing action type and target details.",
    agent=responder
)

generate_report_task = Task(
    description="Summarize all findings and produce an incident report for the SOC dashboard.",
    expected_output="A markdown-formatted incident report.",
    agent=reporter
)

tasks = [
    analyze_failed_logins,
    correlate_successful_logins,
    incident_response_task,
    generate_report_task,
]