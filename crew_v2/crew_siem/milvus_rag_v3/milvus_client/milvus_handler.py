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