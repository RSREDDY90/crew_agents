# crew_execution.py
from crewai import Crew
from agents.soc_agents import investigator, correlator, responder, reporter
from tasks.siem_tasks import (
    analyze_failed_logins,
    correlate_successful_logins,
    incident_response_task,
    generate_report_task
)

if __name__ == "__main__":
    print("\n🚀 Starting SIEM Incident Investigation Crew...\n")

    # Define the Crew with all agents and tasks
    siem_crew = Crew(
        agents=[investigator, correlator, responder, reporter],
        tasks=[
            analyze_failed_logins,
            correlate_successful_logins,
            incident_response_task,
            generate_report_task
        ],
        verbose=True
    )

    # kickoff() runs the full task chain (using prior outputs as context)
    result = siem_crew.kickoff()

    print("\n✅ Final Output:\n")
    print(result)