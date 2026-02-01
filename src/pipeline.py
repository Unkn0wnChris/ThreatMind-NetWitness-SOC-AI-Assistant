#Imported dependecies  
from src.netwitness_parser import NetWitnessParser
from src.log_retrieval import LogRetriever
from typing import List, Dict, Any
import json

#Pipeline function processing Netwitness data
def build_retriever_from_netwitness(
    filepath: str,
    chunked: bool = True,
    max_events_per_chunk: int = 3
) -> LogRetriever:
    """
    Load NetWitness incidents, chunk them, and return a LogRetriever
    with text-ready logs for downstream processing (CorrelationEngine, AI, chatbot).
    
    Args:
        filepath: Path to NetWitness JSON file
        chunked: Whether to chunk alerts/events
        max_events_per_chunk: Max events per chunk

    Returns:
        LogRetriever instance with string logs
    """

    #Load and chunk incidents
    if chunked:
        chunks = NetWitnessParser.parse_and_chunk_incidents(
            filepath, max_events_per_chunk=max_events_per_chunk
        )
    else:
        chunks = NetWitnessParser.load_and_parse_incidents(filepath)

    #Convert each chunk to text for LogRetriever
    text_logs: List[str] = []
    for chunk in chunks:
        if isinstance(chunk, dict):
            # Pretty-print dict as string
            text_logs.append(json.dumps(chunk, ensure_ascii=False))
        else:
            text_logs.append(str(chunk))

    #Return LogRetriever with text logs
    return LogRetriever(text_logs, chunked=chunked)
