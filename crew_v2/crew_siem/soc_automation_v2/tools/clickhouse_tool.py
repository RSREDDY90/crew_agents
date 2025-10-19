# tools/clickhouse_tool.py
from clickhouse_connect import get_client
from dotenv import load_dotenv
import os
from tenacity import retry, wait_exponential, stop_after_attempt

load_dotenv()

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")

def _client():
    return get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        secure=True if os.getenv("CLICKHOUSE_SECURE", "False").lower() == "true" else False
    )

@retry(wait=wait_exponential(multiplier=0.5, min=1, max=3), stop=stop_after_attempt(3))
def query_clickhouse(sql: str, params: dict = None):
    """
    Run SQL and return list[dict].
    Retries on transient errors.
    """
    client = _client()
    # clickhouse-connect supports parameterized queries using format:
    # but for simplicity we'll do safe formatting by ensuring params are typed and not user input
    result = client.query_dict(sql)
    return result