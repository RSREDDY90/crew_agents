# main_rag.py
import logging
from milvus_client.milvus_handler import insert_incidents, collection, insert_incidents as _insert, insert_incidents as dummy
from milvus_client.milvus_handler import insert_incidents as _
from milvus_client import milvus_handler as mh  # easier access
from llm.llm_wrapper import get_llm
from agents.ingestor import IngestorAgent
from agents.retriever import RetrieverAgent
from agents.rag_analyst import RAGAnalystAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

def main():
    llm = get_llm()
    milvus = mh  # the module exposes functions collection, insert_incidents, search_similar
    # Note: our milvus_handler exposes insert_incidents and search_similar as functions
    ingestor = IngestorAgent(milvus)
    retriever = RetrieverAgent(milvus)
    rag = RAGAnalystAgent(llm, retriever)

    # Example malware incidents to ingest
    incidents = [
        {
            "incident_id":"MAL_001",
            "incident_type":"Malware",
            "summary":"Suspicious process executing obfuscated PowerShell script. Dropped binary with name BAD.EXE. C2 domain: evil.example.com",
            "raw":"proc: powershell.exe -EncodedCommand ...; file: BAD.EXE; domain: evil.example.com; sha256: 012345..."
        },
        {
            "incident_id":"MAL_002",
            "incident_type":"Malware",
            "summary":"Endpoint detected lateral movement via SMB; observed suspicious MSI installer comsvc.dll; C2 domain: evil2.example.com",
            "raw":"evt: smb_access ... file: comsvc.dll; domain: evil2.example.com; sha256: abcde..."
        }
    ]

    # ingest
    for inc in incidents:
        ingestor.ingest(inc)

    # run a malware correlation query
    query = "Find ransomware-like activity: obfuscated PowerShell, C2 domains, and dropped EXE"
    out = rag.correlate_malware(query, top_k=5)
    print("\n== LLM OUTPUT ==\n")
    print(out["llm_output"])
    print("\n== Retrieved incidents ==\n")
    for r in out["retrieved"]:
        print(r)

if __name__ == "__main__":
    main()