
from crewai import Agent, LLM
from langchain_google_genai import ChatGoogleGenerativeAI
import os


# llm = ChatGoogleGenerativeAI(model="gemini-1.5-pro", temperature=0.3)

llm = LLM(
    model="gemini/gemini-2.0-flash",
    verbose=True,
    api_key=os.getenv("GOOGLE_API_KEY"),
    temperature=0.7
)

investigator = Agent(
    role="Threat Investigator",
    goal="Detect brute-force login attempts using failed login event patterns.",
    backstory="SOC analyst specialized in login anomaly detection via ClickHouse queries.",
    llm=llm
)

correlator = Agent(
    role="Correlation Analyst",
    goal="Check if the same IP had a successful login after multiple failed attempts.",
    backstory="Expert in event correlation and user behavior analytics.",
    llm=llm
)

responder = Agent(
    role="SOC Responder",
    goal="Generate incident response actions such as blocking IP or alerting admin.",
    backstory="Responsible for incident mitigation and playbook execution.",
    llm=llm
)

reporter = Agent(
    role="Security Reporter",
    goal="Summarize incident findings and create a readable SOC report.",
    backstory="Prepares summaries for SOC dashboards and reports.",
    llm=llm
)