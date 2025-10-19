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