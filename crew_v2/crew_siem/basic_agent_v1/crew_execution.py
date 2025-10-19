from crewai import Crew
from tasks.siem_tasks import tasks
from agents.soc_agents import investigator, correlator, responder, reporter

# Define the Crew (team of agents)
siem_crew = Crew(
    agents=[investigator, correlator, responder, reporter],
    tasks=tasks,
    verbose=True
)

if __name__ == "__main__":
    print("\n🚀 Starting SIEM Incident Investigation Crew...\n")
    result = siem_crew.kickoff()
    print("\n✅ Final Output:\n")
    print(result)