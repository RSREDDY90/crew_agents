"""
Agents: Extract, Store, Retrieve, Correlate
"""

from crewai import Agent, LLM
import uuid
import os
from dotenv import load_dotenv
from tools.tools import embed_text, insert_data, search_data

load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# ============= LLM SETUP =============

llm = None
if GOOGLE_API_KEY:
    llm = LLM(
        model="gemini/gemini-1.5-flash",
        api_key=GOOGLE_API_KEY,
        temperature=0.3
    )
    print("✓ Using Gemini LLM")
else:
    print("⚠️  No GOOGLE_API_KEY - LLM features will be limited")

# ============= AGENT 1: EXTRACT =============

extract_agent = Agent(
    role="SOC Log Parser",
    goal="Extract malware events from logs",
    backstory="Expert at identifying malware signatures in security logs",
    llm=llm,
    verbose=True
)

def extract_events(logs: str) -> list:
    """Parse logs and extract malware events"""
    keywords = ["ransom", "malware", "trojan", "c2", "powershell", "payload", "beacon", "mimikatz", "encrypt", "suspicious"]
    
    events = []
    for line in logs.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        
        lower = line.lower()
        if any(kw in lower for kw in keywords):
            # Classify type
            malware_type = "unknown"
            if "ransom" in lower or "encrypt" in lower:
                malware_type = "ransomware"
            elif "beacon" in lower or "c2" in lower:
                malware_type = "c2_communication"
            elif "powershell" in lower or "payload" in lower:
                malware_type = "dropper"
            elif "mimikatz" in lower:
                malware_type = "credential_theft"
            
            events.append({
                "incident_id": f"inc-{uuid.uuid4().hex[:12]}",
                "malware_type": malware_type,
                "summary": line[:1024],
                "raw": line[:4096]
            })
    
    print(f"✓ Extracted {len(events)} events")
    return events

# ============= AGENT 2: STORE =============

store_agent = Agent(
    role="Vector Database Manager",
    goal="Store incident vectors in Milvus",
    backstory="Expert in vector databases and embeddings",
    llm=llm,
    verbose=True
)

def store_events(events: list) -> dict:
    """Embed and store events in Milvus"""
    if not events:
        return {"stored": 0, "events": []}
    
    records = []
    for event in events:
        vec = embed_text(event.get("summary", ""))
        records.append({
            "incident_id": event["incident_id"],
            "vector": vec,
            "malware_type": event.get("malware_type", "unknown"),
            "summary": event.get("summary", ""),
            "raw": event.get("raw", "")
        })
    
    count = insert_data(records)
    print(f"✓ Stored {count} events")
    
    return {"stored": count, "events": events}

# ============= AGENT 3: RETRIEVE =============

retrieve_agent = Agent(
    role="Vector Search Specialist",
    goal="Find similar incidents using vector search",
    backstory="Expert in semantic similarity search",
    llm=llm,
    verbose=True
)

def retrieve_similar(query: str, top_k: int = 5) -> list:
    """Search for similar incidents"""
    hits = search_data(query, top_k=top_k)
    print(f"✓ Retrieved {len(hits)} incidents")
    return hits

# ============= AGENT 4: CORRELATE =============

correlate_agent = Agent(
    role="Senior Threat Analyst",
    goal="Correlate incidents and generate analysis",
    backstory="15+ years in threat hunting and incident response",
    llm=llm,
    verbose=True
)

def correlate_incidents(new_event: str, retrieved_hits: list) -> str:
    """Generate correlation report using LLM"""
    
    # Build context
    context = ""
    for i, hit in enumerate(retrieved_hits, 1):
        context += f"Incident {i} (Score: {hit.get('score', 0):.3f}):\n"
        context += f"  Type: {hit.get('malware_type')}\n"
        context += f"  Summary: {hit.get('summary')}\n\n"
    
    if not context:
        context = "No similar incidents found.\n"
    
    # Build prompt
    prompt = f"""You are a senior SOC analyst. Analyze this new security event:

NEW EVENT: {new_event}

SIMILAR HISTORICAL INCIDENTS:
{context}

Provide a structured report with:
1. Summary (2-3 sentences)
2. Key Hypotheses (2-3 points)
3. Recommended Actions (3-4 specific steps)

Use clear, actionable language."""
    
    # Get LLM response
    if llm:
        try:
            response = llm.call([{"role": "user", "content": prompt}])
            return response
        except Exception as e:
            return f"[LLM Error: {e}]\n\nPrompt was:\n{prompt}"
    else:
        return f"[No LLM configured]\n\nWould analyze:\n{prompt[:500]}..."
