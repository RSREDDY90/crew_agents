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