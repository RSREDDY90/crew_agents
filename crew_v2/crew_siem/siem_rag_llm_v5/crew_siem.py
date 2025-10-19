"""
SOC SIEM Workflow Functions
"""

import uuid
from tools import embed_text, insert_data, search_data
from agents import llm

# ============= EXTRACT FUNCTION =============
def extract_events(logs: str) -> list:
    """Parse logs and extract malware events"""
    keywords = ["ransom", "malware", "trojan", "c2", "powershell", "payload",
                "beacon", "mimikatz", "encrypt", "suspicious"]
    
    events = []
    for line in logs.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        
        lower = line.lower()
        if any(kw in lower for kw in keywords):
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

# ============= STORE FUNCTION =============
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

# ============= RETRIEVE FUNCTION =============
def retrieve_similar(query: str, top_k: int = 5) -> list:
    """Search for similar incidents"""
    hits = search_data(query, top_k=top_k)
    print(f"✓ Retrieved {len(hits)} incidents")
    return hits

# ============= CORRELATE FUNCTION =============
def correlate_incidents(new_event: str, retrieved_hits: list) -> str:
    """Generate correlation report using LLM"""
    
    context = ""
    for i, hit in enumerate(retrieved_hits, 1):
        context += f"Incident {i} (Score: {hit.get('score', 0):.3f}):\n"
        context += f"  Type: {hit.get('malware_type')}\n"
        context += f"  Summary: {hit.get('summary')}\n\n"
    
    if not context:
        context = "No similar incidents found.\n"
    
    prompt = f"""You are a senior SOC analyst. Analyze this new security event:

NEW EVENT: {new_event}

SIMILAR HISTORICAL INCIDENTS:
{context}

Provide a structured report with:
1. Summary (2-3 sentences)
2. Key Hypotheses (2-3 points)
3. Recommended Actions (3-4 specific steps)

Use clear, actionable language."""
    
    if llm:
        try:
            response = llm.call([{"role": "user", "content": prompt}])
            return response
        except Exception as e:
            print(f"⚠️  LLM Error: {e}")
            return f"[LLM Error: {e}]\n\nFallback Analysis:\n{context}"
    else:
        return f"[No LLM configured]\n\nManual Correlation Required:\n{context}"
