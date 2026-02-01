#Imported dependecies 
from src.ollama_client import ollama_query 

def explain_threat(log: str, question: str) -> str:
    prompt = f"""
    Log:
    {log}

    Question:
    {question}
    """
    return ollama_query(prompt)


