from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection, utility
import random
import string
import os
from dotenv import load_dotenv

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------
load_dotenv()
MILVUS_HOST = os.getenv("MILVUS_HOST")
MILVUS_TOKEN = os.getenv("MILVUS_TOKEN")
COLLECTION_NAME = "test_collection"
VECTOR_DIM = 128

# ---------------------------------------------------
# Connect to Milvus / Zilliz Cloud
# ---------------------------------------------------
connections.connect(
    alias="default",
    host=MILVUS_HOST,
    port="443",
    token=MILVUS_TOKEN,
    secure=True
)
print("✅ Connected to Milvus")

# ---------------------------------------------------
# Drop collection if exists (clean slate)
# ---------------------------------------------------
if utility.has_collection(COLLECTION_NAME):
    utility.drop_collection(COLLECTION_NAME)
    print(f"🧹 Dropped existing collection '{COLLECTION_NAME}'")

# ---------------------------------------------------
# Define schema
# ---------------------------------------------------
fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
    FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=VECTOR_DIM),
    FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=512)
]

schema = CollectionSchema(fields, description="Test collection for vector embeddings")

# ---------------------------------------------------
# Create collection
# ---------------------------------------------------
collection = Collection(name=COLLECTION_NAME, schema=schema)
print(f"✅ Created collection '{COLLECTION_NAME}'")

# ---------------------------------------------------
# Generate sample data
# ---------------------------------------------------
num_vectors = 10
vectors = [[random.random() for _ in range(VECTOR_DIM)] for _ in range(num_vectors)]
texts = ["".join(random.choices(string.ascii_lowercase, k=10)) for _ in range(num_vectors)]

# ---------------------------------------------------
# Insert data
# ---------------------------------------------------
collection.insert([vectors, texts])
collection.flush()
print(f"✅ Inserted {num_vectors} records")

# ---------------------------------------------------
# Create index on embedding field
# ---------------------------------------------------
index_params = {
    "metric_type": "L2",
    "index_type": "IVF_FLAT",
    "params": {"nlist": 64}
}
collection.create_index(field_name="embedding", index_params=index_params)
print("✅ Created index on 'embedding' field")

# ---------------------------------------------------
# Load collection into memory
# ---------------------------------------------------
collection.load()
print("✅ Collection loaded into memory")

# ---------------------------------------------------
# Verify count
# ---------------------------------------------------
print(f"Total entities: {collection.num_entities}")
print("🎉 Setup complete.")