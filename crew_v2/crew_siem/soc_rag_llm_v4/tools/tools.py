"""
Tools: Embedding and Milvus operations
"""

from sentence_transformers import SentenceTransformer
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection, utility
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration
MILVUS_HOST = os.getenv("MILVUS_HOST")
MILVUS_TOKEN = os.getenv("MILVUS_TOKEN")
COLLECTION_NAME = os.getenv("MILVUS_COLLECTION", "malware_incidents")
VECTOR_DIM = int(os.getenv("VECTOR_DIM", "384"))

# ============= EMBEDDINGS =============

print("Loading embedding model...")
model = SentenceTransformer("all-MiniLM-L6-v2")

def embed_text(text: str) -> list:
    """Convert text to 384-dim vector"""
    if not text:
        return [0.0] * VECTOR_DIM
    vec = model.encode(text).tolist()
    # Ensure correct dimension
    if len(vec) < VECTOR_DIM:
        vec += [0.0] * (VECTOR_DIM - len(vec))
    elif len(vec) > VECTOR_DIM:
        vec = vec[:VECTOR_DIM]
    return vec

# ============= MILVUS CONNECTION =============

print(f"Connecting to Milvus at {MILVUS_HOST}...")

# Detect cloud vs local
is_cloud = "cloud" in MILVUS_HOST.lower() or "zilliz" in MILVUS_HOST.lower()

if is_cloud:
    connections.connect(
        alias="default",
        host=MILVUS_HOST,
        port="443",
        token=MILVUS_TOKEN,
        secure=True
    )
else:
    # Local connection
    if MILVUS_TOKEN and ":" in MILVUS_TOKEN:
        user, pwd = MILVUS_TOKEN.split(":", 1)
        connections.connect(
            alias="default",
            host=MILVUS_HOST or "localhost",
            port="19530",
            user=user,
            password=pwd
        )
    else:
        connections.connect(
            alias="default",
            host=MILVUS_HOST or "localhost",
            port="19530"
        )

print("✓ Connected to Milvus")

# ============= COLLECTION SETUP =============

def setup_collection():
    """Create or load collection"""
    if utility.has_collection(COLLECTION_NAME):
        col = Collection(COLLECTION_NAME)
        print(f"✓ Loaded collection: {COLLECTION_NAME}")
        return col
    
    # Create new collection
    fields = [
        FieldSchema(name="incident_id", dtype=DataType.VARCHAR, is_primary=True, max_length=64),
        FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=VECTOR_DIM),
        FieldSchema(name="malware_type", dtype=DataType.VARCHAR, max_length=128),
        FieldSchema(name="summary", dtype=DataType.VARCHAR, max_length=1024),
        FieldSchema(name="raw", dtype=DataType.VARCHAR, max_length=4096)
    ]
    
    schema = CollectionSchema(fields, description="Malware incidents")
    col = Collection(name=COLLECTION_NAME, schema=schema)
    
    # Create index
    col.create_index(
        field_name="vector",
        index_params={"index_type": "AUTOINDEX", "metric_type": "COSINE", "params": {}}
    )
    
    print(f"✓ Created collection: {COLLECTION_NAME}")
    return col

collection = setup_collection()

# ============= INSERT DATA =============

def insert_data(records: list) -> int:
    """Insert records into Milvus"""
    if not records:
        print("⚠️  No records to insert")
        return 0
    
    # Prepare columnar data
    ids = [r["incident_id"] for r in records]
    vecs = [r["vector"] for r in records]
    types = [r.get("malware_type", "unknown") for r in records]
    summaries = [r.get("summary", "") for r in records]
    raws = [r.get("raw", "") for r in records]
    
    # Insert
    collection.insert([ids, vecs, types, summaries, raws])
    collection.flush()
    collection.load()
    
    print(f"✓ Inserted {len(ids)} records (Total: {collection.num_entities})")
    return len(ids)

# ============= SEARCH DATA =============

def search_data(query_text: str, top_k: int = 5) -> list:
    """Search for similar incidents"""
    # Embed query
    query_vec = embed_text(query_text)
    
    # Ensure collection is loaded
    collection.load()
    
    # Check if collection has data
    if collection.num_entities == 0:
        print("⚠️  Collection is empty!")
        return []
    
    # Search
    results = collection.search(
        data=[query_vec],
        anns_field="vector",
        param={"metric_type": "COSINE", "params": {"nprobe": 10}},
        limit=top_k,
        output_fields=["incident_id", "malware_type", "summary", "raw"]
    )
    
    # Parse results
    hits = []
    for hit in results[0]:
        hits.append({
            "incident_id": hit.entity.get("incident_id"),
            "malware_type": hit.entity.get("malware_type"),
            "summary": hit.entity.get("summary"),
            "raw": hit.entity.get("raw"),
            "score": float(hit.distance)
        })
    
    print(f"✓ Found {len(hits)} similar incidents")
    return hits
