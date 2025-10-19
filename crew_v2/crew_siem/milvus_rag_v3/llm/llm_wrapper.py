# llm/llm_wrapper.py
import os
from dotenv import load_dotenv
load_dotenv()
USE_MOCK = os.getenv("USE_MOCK_LLM", "true").lower() in ("1","true","yes")

class MockLLM:
    def generate(self, prompt: str):
        return f"[MockLLM] Correlation summary for prompt:\n{prompt[:1000]}"

# Simple OpenAI wrapper (optional)
class OpenAIWrapper:
    def __init__(self, api_key=None, model="gpt-4o" or "gpt-4"):
        try:
            import openai
        except Exception:
            raise RuntimeError("openai package required for OpenAIWrapper")
        self.openai = openai
        self.openai.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4")  # change as needed

    def generate(self, prompt: str):
        resp = self.openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role":"user","content": prompt}],
            max_tokens=512,
            temperature=0.0
        )
        return resp.choices[0].message.content

def get_llm():
    if USE_MOCK:
        return MockLLM()
    else:
        return OpenAIWrapper()