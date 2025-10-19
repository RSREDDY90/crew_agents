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