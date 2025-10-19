"""
Milvus Vector Database Tools
"""

from pymilvus import connections, Collection, utility, FieldSchema, CollectionSchema, DataType
from sentence_transformers import SentenceTransformer
import os

# ============= CONFIGURATION =============
MILVUS_HOST = os.getenv("MILVUS_HOST", "localhost")
MILVUS_PORT = os.getenv("MILVUS_PORT", "19530")
COLLECTION_NAME = "soc_incidents"

# Configuration
MILVUS_HOST = os.getenv("MILVUS_HOST")
MILVUS_TOKEN = os.getenv("MILVUS_TOKEN")
COLLECTION_NAME = os.getenv("MILVUS_COLLECTION", "malware_incidents")
VECTOR_DIM = int(os.getenv("VECTOR_DIM", "384"))


# ============= EMBEDDING MODEL =============
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
print("✓ Loaded embedding model: all-MiniLM-L6-v2")

# ============= MILVUS CONNECTION =============
def init_milvus():
    """Initialize Milvus connection and collection"""
    
    connections.connect(
        alias="default",
        host=MILVUS_HOST,
        port="443",
        token=MILVUS_TOKEN,
        secure=True
    )

    print(f"✓ Connected to Milvus at {MILVUS_HOST}:{MILVUS_PORT}")
    
    # Create collection if not exists
    if not utility.has_collection(COLLECTION_NAME):
        fields = [
            FieldSchema(name="incident_id", dtype=DataType.VARCHAR, is_primary=True, max_length=128),
            FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=384),
            FieldSchema(name="malware_type", dtype=DataType.VARCHAR, max_length=256),
            FieldSchema(name="summary", dtype=DataType.VARCHAR, max_length=2048),
            FieldSchema(name="raw", dtype=DataType.VARCHAR, max_length=8192)
        ]
        schema = CollectionSchema(fields, description="SOC incident vectors")
        collection = Collection(name=COLLECTION_NAME, schema=schema)
        
        # Create HNSW index
        index_params = {
            "metric_type": "COSINE",
            "index_type": "HNSW",
            "params": {"M": 16, "efConstruction": 256}
        }
        collection.create_index(field_name="vector", index_params=index_params)
        print(f"✓ Created collection: {COLLECTION_NAME}")
    else:
        collection = Collection(name=COLLECTION_NAME)
        print(f"✓ Loaded existing collection: {COLLECTION_NAME}")
    
    collection.load()
    return collection

# Initialize collection
collection = init_milvus()

# ============= EMBEDDING FUNCTION =============
def embed_text(text: str) -> list:
    """Generate embedding vector for text"""
    return embedding_model.encode(text).tolist()

# ============= INSERT FUNCTION =============
def insert_data(records: list) -> int:
    """Insert records into Milvus"""
    if not records:
        return 0
    
    ids = [r["incident_id"] for r in records]
    vectors = [r["vector"] for r in records]
    types = [r["malware_type"] for r in records]
    summaries = [r["summary"] for r in records]
    raws = [r["raw"] for r in records]
    
    collection.insert([ids, vectors, types, summaries, raws])
    collection.flush()
    
    return len(records)

# ============= SEARCH FUNCTION =============
def search_data(query: str, top_k: int = 5) -> list:
    """Search for similar incidents"""
    query_vec = embed_text(query)
    
    search_params = {"metric_type": "COSINE", "params": {"ef": 128}}
    results = collection.search(
        data=[query_vec],
        anns_field="vector",
        param=search_params,
        limit=top_k,
        output_fields=["incident_id", "malware_type", "summary", "raw"]
    )
    
    hits = []
    for result in results[0]:
        hits.append({
            "incident_id": result.entity.get("incident_id"),
            "malware_type": result.entity.get("malware_type"),
            "summary": result.entity.get("summary"),
            "raw": result.entity.get("raw"),
            "score": result.distance
        })
    
    return hits
