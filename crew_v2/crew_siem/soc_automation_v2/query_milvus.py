
from pymilvus import (
    connections,
    FieldSchema,
    CollectionSchema,
    DataType,
    Collection,
    utility
)

import os
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

load_dotenv()

MILVUS_HOST = os.getenv("MILVUS_HOST")
MILVUS_TOKEN = os.getenv("MILVUS_TOKEN")
COLLECTION_NAME = "siem_incidents"
VECTOR_DIM = 384

# -----------------------
# Connect to Milvus
# -----------------------
connections.connect(
    alias="default",
    host=MILVUS_HOST,
    port="443",
    token=MILVUS_TOKEN,
    secure=True
)

# -----------------------
# Load collection
# -----------------------
if not utility.has_collection(COLLECTION_NAME):
    raise ValueError(f"Collection '{COLLECTION_NAME}' does not exist.")
collection = Collection(COLLECTION_NAME)
collection.load()
print(f"✅ Collection '{COLLECTION_NAME}' loaded")

# -----------------------
# Embedding model for queries
# -----------------------
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# -----------------------
# Query by filters (ip or tenant_id)
# -----------------------
def query_incidents_by_filter(ip=None, tenant_id=None, limit=10):
    expr_parts = []
    if ip:
        expr_parts.append(f"ip == '{ip}'")
    if tenant_id:
        expr_parts.append(f"tenant_id == '{tenant_id}'")
    expr = " and ".join(expr_parts) if expr_parts else None

    results = collection.query(
        expr=expr,
        output_fields=["incident_id", "ip", "tenant_id", "failed_count"]
    )
    print(f"🔍 Found {len(results)} incidents matching filters")
    return results[:limit]

# -----------------------
# Query by vector similarity
# -----------------------
def query_similar_incidents(evidence_text, top_k=5):
    vector = embedding_model.encode(evidence_text).tolist()
    search_params = {"metric_type": "COSINE", "params": {"nprobe": 10}}

    results = collection.search(
        data=[vector],
        anns_field="description_vector",
        param=search_params,
        limit=top_k,
        output_fields=["incident_id", "ip", "tenant_id", "failed_count"]
    )
    incidents = []
    for hits in results:
        for hit in hits:
            incidents.append({
                "incident_id": hit.entity.get("incident_id"),
                "ip": hit.entity.get("ip"),
                "tenant_id": hit.entity.get("tenant_id"),
                "failed_count": hit.entity.get("failed_count"),
                "score": hit.distance
            })
    print(f"🔍 Found {len(incidents)} similar incidents")
    return incidents

# -----------------------
# Example usage
# -----------------------
if __name__ == "__main__":
    print("=== Filter by IP ===")
    ip_results = query_incidents_by_filter(ip="192.168.0.1")
    print(ip_results)

    print("\n=== Filter by Tenant ID ===")
    tenant_results = query_incidents_by_filter(tenant_id="tenant_123")
    print(tenant_results)

    print("\n=== Vector similarity search ===")
    evidence_text = "user1 success 2025-10-18T12:00:00"
    similar_results = query_similar_incidents(evidence_text)
    print(similar_results)