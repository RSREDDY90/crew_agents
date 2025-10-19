====================================

mkdir crew_siem
cd crew_siem
uv venv --python 3.12
source .venv/bin/activate

====================================
libs :

uv pip install "crewai[tools]" "langchain-google-genai" "clickhouse-connect" "requests"

uv pip install crewai clickhouse-connect requests tenacity python-dotenv

uv pip install sentence-transformers

uv pip install pymilvus

reference 
pip3 install pymilvus==2.5.3

====================================

RUN / Execute : 

uv run python crew_execution.py

====================================

