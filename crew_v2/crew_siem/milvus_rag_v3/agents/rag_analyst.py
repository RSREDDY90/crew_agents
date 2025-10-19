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