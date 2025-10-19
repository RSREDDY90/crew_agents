"""
Main Entry Point for SOC SIEM Workflow
"""

from dotenv import load_dotenv
from crew_siem import extract_events, store_events, retrieve_similar, correlate_incidents

load_dotenv()

def run_soc_workflow(logs: str, query: str = None):
    """
    Main SOC workflow: Extract -> Store -> Retrieve -> Correlate
    """
    print("\n" + "="*80)
    print("RUNNING SOC WORKFLOW")
    print("="*80 + "\n")
    
    # Step 1: Extract malware events
    print("Step 1: Extracting malware events...")
    events = extract_events(logs)
    if not events:
        return "No malware events detected in logs."
    
    # Step 2: Store events in Milvus
    print("\nStep 2: Storing events in Milvus...")
    result = store_events(events)
    print(f"Stored {result['stored']} events\n")
    
    # Step 3: Retrieve similar incidents
    print("Step 3: Retrieving similar incidents...")
    search_query = query if query else events[0]["summary"]
    similar = retrieve_similar(search_query, top_k=5)

    print(f"Retrieved {len(similar)} similar incidents\n")
    print(f"Search Query: {search_query}\n")
    print(f"Similar Incidents: {similar}\n")

    
    # Step 4: Correlate and generate report
    print("\nStep 4: Generating correlation report...\n")
    report = correlate_incidents(search_query, similar)
    
    return report


if __name__ == "__main__":
    # Sample malicious logs
    sample_logs = """
2025-10-19 14:23:11 WARNING: Suspicious powershell execution detected on host WIN-SRV-01
2025-10-19 14:23:45 ALERT: C2 beacon communication to 192.168.1.100:443 blocked
2025-10-19 14:24:12 CRITICAL: Ransomware encryption activity detected in C:\\Users\\Documents
2025-10-19 14:25:33 INFO: User login successful from 10.0.0.5
2025-10-19 14:26:01 WARNING: Mimikatz credential dumping attempt on DC-01
2025-10-19 14:27:18 ALERT: Trojan payload downloaded from malicious domain evil.com
    """
    
    # Run workflow
    report = run_soc_workflow(
        logs=sample_logs,
        query="ransomware encryption activity detected"
    )
    
    # Display results
    print("\n" + "="*80)
    print("THREAT INTELLIGENCE REPORT")
    print("="*80 + "\n")
    print(report)
