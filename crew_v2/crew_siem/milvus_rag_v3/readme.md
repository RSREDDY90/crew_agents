============================================================================================================

/Users/sreddy/quilr/local_workspace/crew_v2/crew_siem/soc_automation_rag_v3

RUN : 

uv run python crew_execution.py

DEBUG : 
uv run python -m pdb crew_execution.py


============================================================================================================
-- create table for login events
CREATE TABLE IF NOT EXISTS siem_login_events
(
    event_time DateTime64(3),
    tenant_id String,
    user_id String,
    ip String,
    event_type String,        -- "failed" or "success"
    message String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, ip, event_time);

-- insert sample data (example)
INSERT INTO siem_login_events (event_time, tenant_id, user_id, ip, event_type, message) VALUES
('2025-10-18 10:00:00', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:00:20', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:01:05', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:01:30', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:02:10', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:02:40', 't1', 'alice', '10.0.0.5', 'failed', 'invalid password'),
('2025-10-18 10:03:00', 't1', 'alice', '10.0.0.5', 'success', 'logged in');




================================================================================================================


Great — below is a complete, end-to-end RAG pipeline for a Malware Correlation use case using:
	•	Milvus (Zilliz Cloud / self-hosted) as vector store
	•	SentenceTransformers (all-MiniLM-L6-v2) for embeddings (free)
	•	A pluggable LLM wrapper that supports Mock and OpenAI (switch by env var)
	•	Agents: Ingestor (stores incidents), Retriever (fetches similar incidents), RAGAnalyst (builds context + calls LLM to correlate/summarize)
	•	Robust logging and safe index handling for Zilliz Cloud (uses AUTOINDEX for quick testing)

Drop these files into a new project (suggested layout below). I’ll explain how to run them afterwards.

⸻

Project layout

crew_cyber_rag/
├── .env
├── main_rag.py
├── requirements.txt
├── milvus_client/
│   └── milvus_handler.py
├── embeddings/
│   └── embedder.py
├── llm/
│   └── llm_wrapper.py
├── agents/
│   ├── ingestor.py
│   ├── retriever.py
│   └── rag_analyst.py
└── README.md


⸻

1) requirements.txt

pymilvus>=2.4.0
sentence-transformers>=2.2.2
python-dotenv
openai                # optional if you want to use OpenAI LLM

Install:

pip install -r requirements.txt


⸻

2) .env (fill your values)

MILVUS_HOST=https://YOUR_ZILLIZ_HOST
MILVUS_TOKEN=YOUR_ZILLIZ_API_TOKEN

# Optional if using OpenAI LLM
OPENAI_API_KEY=
USE_MOCK_LLM=true   # set to "false" to use OpenAI (if OPENAI_API_KEY provided)


⸻

3) milvus_client/milvus_handler.py

# milvus_client/milvus_handler.py
import os
import logging
from dotenv import load_dotenv
from pymilvus import (
    connections,
    FieldSchema,
    CollectionSchema,
    DataType,
    Collection,
    utility
)

load_dotenv()
logger = logging.getLogger("milvus_handler")
logger.setLevel(logging.INFO)
if not logger.handlers:
    import sys
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)

MILVUS_HOST = os.getenv("MILVUS_HOST")
MILVUS_TOKEN = os.getenv("MILVUS_TOKEN")
COLLECTION_NAME = os.getenv("MILVUS_COLLECTION", "cyber_incidents")
VECTOR_DIM = int(os.getenv("VECTOR_DIM", "384"))

# Connect
connections.connect(alias="default", host=MILVUS_HOST, port="443", token=MILVUS_TOKEN, secure=True)
logger.info("Connected to Milvus")

# Create or load collection
def ensure_collection():
    if utility.has_collection(COLLECTION_NAME):
        logger.info(f"Loading existing collection: {COLLECTION_NAME}")
        return Collection(COLLECTION_NAME)
    # define schema
    fields = [
        FieldSchema(name="incident_id", dtype=DataType.VARCHAR, is_primary=True, max_length=64),
        FieldSchema(name="description_vector", dtype=DataType.FLOAT_VECTOR, dim=VECTOR_DIM),
        FieldSchema(name="incident_type", dtype=DataType.VARCHAR, max_length=64),
        FieldSchema(name="summary", dtype=DataType.VARCHAR, max_length=1024),
        FieldSchema(name="raw", dtype=DataType.VARCHAR, max_length=4096),
    ]
    schema = CollectionSchema(fields, description="Cybersecurity incidents")
    coll = Collection(name=COLLECTION_NAME, schema=schema)
    logger.info(f"Created collection: {COLLECTION_NAME}")

    # Create AUTOINDEX for cloud friendly immediate use
    index_params = {
        "index_type": "AUTOINDEX",
        "metric_type": "COSINE",
        "params": {}
    }
    logger.info("Creating AUTOINDEX for description_vector...")
    coll.create_index("description_vector", index_params)
    logger.info("AUTOINDEX created.")
    return coll

collection = ensure_collection()

def insert_incidents(records):
    """
    records: list of dicts with keys:
      - incident_id (str)
      - incident_type (str)
      - summary (str)
      - raw (str)
      - vector (list[float])  optional: if not present, must compute external
    """
    if not records:
        return 0
    ids = []
    vectors = []
    types = []
    summaries = []
    raws = []
    for r in records:
        ids.append(r.get("incident_id"))
        vectors.append(r.get("vector"))
        types.append(r.get("incident_type",""))
        summaries.append(r.get("summary",""))
        raws.append(r.get("raw",""))
    collection.insert([ids, vectors, types, summaries, raws])
    collection.flush()
    logger.info(f"Inserted {len(ids)} records into {COLLECTION_NAME}")
    # load to memory for searching
    collection.load()
    return len(ids)

def search_similar(vector, top_k=5, output_fields=None):
    collection.load()
    params = {"metric_type": "COSINE", "params": {"nprobe": 10}}
    output_fields = output_fields or ["incident_id", "incident_type", "summary", "raw"]
    results = collection.search(
        data=[vector],
        anns_field="description_vector",
        param=params,
        limit=top_k,
        output_fields=output_fields
    )
    # results is list of hits lists (one per query)
    hits = results[0] if results else []
    out = []
    for hit in hits:
        ent = hit.entity
        out.append({
            "incident_id": ent.get("incident_id"),
            "incident_type": ent.get("incident_type"),
            "summary": ent.get("summary"),
            "raw": ent.get("raw"),
            "score": float(hit.distance)
        })
    return out


⸻

4) embeddings/embedder.py

# embeddings/embedder.py
from sentence_transformers import SentenceTransformer
import os
from dotenv import load_dotenv
load_dotenv()

MODEL_NAME = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
_model = None

def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model

def embed_text(text):
    """
    Returns a list[float] of embedding vector (length matches VECTOR_DIM).
    """
    model = get_model()
    vec = model.encode(text)
    # ensure python list
    return vec.tolist()


⸻

5) llm/llm_wrapper.py — Mock + OpenAI wrapper

# llm/llm_wrapper.py
import os
from dotenv import load_dotenv
load_dotenv()
USE_MOCK = os.getenv("USE_MOCK_LLM", "true").lower() in ("1","true","yes")

class MockLLM:
    def generate(self, prompt: str):
        return f"[MockLLM] Correlation summary for prompt:\n{prompt[:1000]}"

# Simple OpenAI wrapper (optional)
class OpenAIWrapper:
    def __init__(self, api_key=None, model="gpt-4o" or "gpt-4"):
        try:
            import openai
        except Exception:
            raise RuntimeError("openai package required for OpenAIWrapper")
        self.openai = openai
        self.openai.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4")  # change as needed

    def generate(self, prompt: str):
        resp = self.openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role":"user","content": prompt}],
            max_tokens=512,
            temperature=0.0
        )
        return resp.choices[0].message.content

def get_llm():
    if USE_MOCK:
        return MockLLM()
    else:
        return OpenAIWrapper()


⸻

6) agents/ingestor.py

# agents/ingestor.py
import logging
from embeddings.embedder import embed_text
logger = logging.getLogger("Ingestor")

class IngestorAgent:
    def __init__(self, milvus_handler):
        self.milvus = milvus_handler

    def ingest(self, incident):
        # incident: dict with keys: incident_id, incident_type, summary, raw
        text_for_embedding = f"{incident.get('incident_type','')} {incident.get('summary','')} {incident.get('raw','')}"
        vec = embed_text(text_for_embedding)
        incident_obj = {
            "incident_id": incident["incident_id"],
            "incident_type": incident.get("incident_type",""),
            "summary": incident.get("summary",""),
            "raw": incident.get("raw",""),
            "vector": vec
        }
        count = self.milvus.insert_incidents([incident_obj])
        logger.info(f"Ingestor: ingested {incident['incident_id']}")
        return count


⸻

7) agents/retriever.py

# agents/retriever.py
import logging
from embeddings.embedder import embed_text
logger = logging.getLogger("Retriever")

class RetrieverAgent:
    def __init__(self, milvus_handler):
        self.milvus = milvus_handler

    def retrieve_by_text(self, text_query, top_k=5):
        vec = embed_text(text_query)
        hits = self.milvus.search_similar(vec, top_k=top_k)
        logger.info(f"Retriever: found {len(hits)} hits for query")
        return hits


⸻

8) agents/rag_analyst.py

# agents/rag_analyst.py
import logging
logger = logging.getLogger("RAGAnalyst")

class RAGAnalystAgent:
    def __init__(self, llm, retriever):
        self.llm = llm
        self.retriever = retriever

    def correlate_malware(self, query_text, top_k=5):
        # 1) retrieve similar incidents
        hits = self.retriever.retrieve_by_text(query_text, top_k=top_k)

        # 2) build RAG context
        context_parts = []
        for i, h in enumerate(hits, start=1):
            context_parts.append(f"Incident {i}: id={h['incident_id']}, type={h['incident_type']}, summary={h['summary']}, raw={h['raw']}, score={h['score']:.4f}")

        context = "\n\n".join(context_parts) if context_parts else "No similar incidents found."
        prompt = (
            "You are a cybersecurity analyst. Correlate the following query with stored incidents.\n\n"
            f"Query: {query_text}\n\nRetrieved incidents:\n{context}\n\n"
            "Provide a concise correlation summary: list likely relationships, suggested severity, recommended next steps (triage, containment, forensics, IOC extraction)."
        )

        result = self.llm.generate(prompt)
        return {
            "prompt": prompt,
            "llm_output": result,
            "retrieved": hits
        }


⸻

9) main_rag.py — Put it all together (malware correlation use case)

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


⸻

Notes & Best Practices
	1.	Indexing on Zilliz Cloud: For quick dev/testing use AUTOINDEX. For production, use IVF_FLAT, HNSW, etc., and build indices after you have a large corpus. Building can be asynchronous — check your cloud console and utility helpers.
	2.	Embeddings: all-MiniLM-L6-v2 gives 384-dim vectors. Keep VECTOR_DIM=384 in .env or defaults. For higher quality/semantic matching, try larger sentence-transformer models.
	3.	LLM: This code uses MockLLM by default (controlled by USE_MOCK_LLM in .env). To enable OpenAI:
	•	Install openai
	•	Set OPENAI_API_KEY and USE_MOCK_LLM=false
	•	The OpenAIWrapper uses ChatCompletion as example; adapt model name to your account.
	4.	Security: Don’t commit API keys. Use .env and secret management.
	5.	Extending for Malware correlation:
	•	Enrich stored metadata (IOCs, file hashes, YARA, process tree).
	•	Add agent to parse raw logs into structured fields for better search/filtering.
	•	Add scheduled re-indexing / periodic export.
	6.	Testing: Start with USE_MOCK_LLM=true and MILVUS creds set. Run:

python main_rag.py



⸻

If you want, I can:
	•	Provide a single-file minimal demo (easy to run).
	•	Add a query/CLI tool to search by IP, domain, file hash.
	•	Replace MockLLM with a local LLM (e.g., llama.cpp wrapper or Hugging Face inference) example.

Which next step would you like?

=====================================================================================================================