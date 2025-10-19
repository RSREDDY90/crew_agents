# soc_agents.py
from crewai import Agent, LLM
from langchain_google_genai import ChatGoogleGenerativeAI
import os


llm = LLM(
    model="gemini/gemini-2.0-flash",
    verbose=True,
    api_key=os.getenv("GOOGLE_API_KEY"),
    temperature=0.7
)

# === Investigator Agent ===
investigator = Agent(
    name="Investigator",
    role="Investigate failed login attempts and find suspicious patterns.",
    goal="Identify brute-force attempts or credential stuffing activity.",
    backstory=(
        "You are a seasoned SOC analyst who investigates failed logins "
        "across multiple systems to uncover possible brute-force attacks. "
        "You use correlation logic to find repeated failed attempts in short time windows."
    ),
    llm=llm,
    disable_reasoning=True,  # <-- disable internal LLM calls
    verbose=True
)

# === Correlator Agent ===
correlator = Agent(
    name="Correlator",
    role="Correlate failed logins with later successful events.",
    goal="Detect when attackers gain access after multiple failed attempts.",
    backstory=(
        "You are a correlation expert who links failed and successful login events "
        "to identify compromised accounts."
    ),
    llm=llm,
    disable_reasoning=True,  # <-- disable internal LLM calls
    verbose=True
)

# === Responder Agent ===
responder = Agent(
    name="Responder",
    role="Respond to security incidents with actionable recommendations.",
    goal="Suggest containment, eradication, and recovery actions.",
    backstory=(
        "You are an incident responder who crafts detailed containment plans "
        "and alerts SOC teams via automated systems."
    ),
    llm=llm,
    disable_reasoning=True,  # <-- disable internal LLM calls
    verbose=True
)

# === Reporter Agent ===
reporter = Agent(
    name="Reporter",
    role="Summarize incidents and provide executive-level reports.",
    goal="Generate markdown-based SIEM investigation reports.",
    backstory=(
        "You are a senior SOC reporter who turns raw findings into concise "
        "and actionable executive summaries."
    ),
    llm=llm,
    disable_reasoning=True,  # <-- disable internal LLM calls
    verbose=True
)