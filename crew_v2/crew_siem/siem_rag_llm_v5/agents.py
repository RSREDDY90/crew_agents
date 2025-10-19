"""
SOC Agents: Extract, Store, Retrieve, Correlate
"""

from crewai import Agent, LLM
import os

# ============= LLM SETUP =============
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
os.environ["GEMINI_API_KEY"] = GOOGLE_API_KEY if GOOGLE_API_KEY else ""
os.environ["OPENAI_API_KEY"] = "fake-key"

llm = None
if GOOGLE_API_KEY:
    llm = LLM(
        model="gemini/gemini-2.0-flash",
        temperature=0.3
    )
    print("✓ Using Gemini LLM")
else:
    print("⚠️  No GOOGLE_API_KEY - LLM features will be limited")

# ============= AGENTS =============

extract_agent = Agent(
    role="SOC Log Parser",
    goal="Extract malware events from security logs with high accuracy",
    backstory="Expert SOC analyst with 10+ years identifying malware signatures in logs",
    llm=None,
    verbose=True,
    allow_delegation=False
)

store_agent = Agent(
    role="Vector Database Manager",
    goal="Store incident vectors efficiently in Milvus",
    backstory="Database engineer specializing in vector embeddings and semantic search",
    llm=None,
    verbose=True,
    allow_delegation=False
)

retrieve_agent = Agent(
    role="Vector Search Specialist",
    goal="Find the most relevant similar incidents using vector similarity",
    backstory="Information retrieval expert with deep knowledge of semantic search algorithms",
    llm=None,
    verbose=True,
    allow_delegation=False
)

correlate_agent = Agent(
    role="Senior Threat Analyst",
    goal="Correlate incidents and generate actionable threat intelligence reports",
    backstory="15+ years in threat hunting, incident response, and malware analysis",
    llm=llm,
    verbose=True,
    allow_delegation=False
)
