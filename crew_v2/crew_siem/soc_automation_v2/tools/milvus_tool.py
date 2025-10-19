from pymilvus import (
    connections,
    FieldSchema,
    CollectionSchema,
    DataType,
    Collection,
    utility
)
import uuid
import os
import random
import time
from dotenv import load_dotenv
import logging

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MILVUS_HOST = os.getenv("MILVUS_HOST")
MILVUS_TOKEN = os.getenv("MILVUS_TOKEN")
COLLECTION_NAME = "siem_incidents"
VECTOR_DIM = 384

# -----------------------
# Connect to Milvus / Zilliz Cloud
# -----------------------
connections.connect(
    alias="default",
    host=MILVUS_HOST,
    port="443",
    token=MILVUS_TOKEN,
    secure=True
)
logger.info("✅ Connected to Milvus")

# -----------------------
# Drop and recreate collection for clean setup
# -----------------------
if utility.has_collection(COLLECTION_NAME):
    utility.drop_collection(COLLECTION_NAME)
    logger.info(f"🧹 Dropped existing collection '{COLLECTION_NAME}'")

# -----------------------
# Define schema
# -----------------------
fields = [
    FieldSchema(name="incident_id", dtype=DataType.VARCHAR, is_primary=True, max_length=64),
    FieldSchema(name="description_vector", dtype=DataType.FLOAT_VECTOR, dim=VECTOR_DIM),
    FieldSchema(name="ip", dtype=DataType.VARCHAR, max_length=64),
    FieldSchema(name="tenant_id", dtype=DataType.VARCHAR, max_length=64),
    FieldSchema(name="failed_count", dtype=DataType.INT64),
]

schema = CollectionSchema(fields, description="SIEM incidents with vector embeddings")

collection = Collection(name=COLLECTION_NAME, schema=schema)
logger.info(f"✅ Created collection '{COLLECTION_NAME}'")

# -----------------------
# Create index (AUTOINDEX avoids async delay)
# -----------------------
index_params = {
    "index_type": "AUTOINDEX",
    "metric_type": "COSINE",
    "params": {}
}
logger.info("🔧 Creating index (AUTOINDEX)...")
collection.create_index("description_vector", index_params)
logger.info("✅ AUTOINDEX created successfully")

# -----------------------
# Function to store incidents
# -----------------------
def store_incidents_to_milvus(incidents):
    logger.info("🔄 Storing incidents to Milvus...")
    if not incidents:
        logger.warning("⚠️ No incidents to store")
        return 0

    incident_ids, vectors, ips, tenants, failed_counts = [], [], [], [], []

    for inc in incidents:
        incident_ids.append(inc.get("incident_id", str(uuid.uuid4())))
        vectors.append([random.random() for _ in range(VECTOR_DIM)])
        ips.append(inc.get("ip", ""))
        tenants.append(inc.get("tenant_id", ""))
        failed_counts.append(inc.get("failed_count", 0))

    # Insert and flush
    collection.insert([incident_ids, vectors, ips, tenants, failed_counts])
    collection.flush()
    logger.info(f"✅ Inserted {len(incident_ids)} incidents")

    # Load collection
    logger.info("📦 Loading collection into memory...")
    collection.load()
    logger.info(f"✅ Collection '{COLLECTION_NAME}' loaded into memory")

    return len(incident_ids)


# -----------------------
# Example data
# -----------------------
if __name__ == "__main__":
    sample_incidents = [
        {
            "incident_id": "INC001",
            "ip": "192.168.1.10",
            "tenant_id": "tenant_01",
            "failed_count": 3,
        },
        {
            "incident_id": "INC002",
            "ip": "10.0.0.45",
            "tenant_id": "tenant_02",
            "failed_count": 1,
        }
    ]

    store_incidents_to_milvus(sample_incidents)