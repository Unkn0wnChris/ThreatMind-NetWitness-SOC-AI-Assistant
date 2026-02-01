"""
Diagnostic script to check SOCGPT setup
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 60)
print("SOCGPT Diagnostic Check")
print("=" * 60)

# Check Python version
print(f"\n✓ Python Version: {sys.version}")

# Check imports
print("\n📦 Checking imports...")
try:
    import streamlit
    print(f"  ✓ Streamlit: {streamlit.__version__}")
except ImportError as e:
    print(f"  ✗ Streamlit: {e}")

try:
    import ollama
    print(f"  ✓ Ollama: installed")
except ImportError as e:
    print(f"  ✗ Ollama: {e}")

try:
    import yaml
    print(f"  ✓ PyYAML: installed")
except ImportError as e:
    print(f"  ✗ PyYAML: {e}")

# Check Ollama connection
print("\n🔌 Checking Ollama connection...")
try:
    from src.ollama_client import check_ollama_connection, MODEL
    if check_ollama_connection():
        print(f"  ✓ Ollama server is running")
        print(f"  ✓ Using model: {MODEL}")
        
        # List available models
        import ollama
        models = ollama.list()
        if models and models.models:
            print(f"  ✓ Available models:")
            for model in models.models:
                print(f"    - {model.model}")
        else:
            print(f"  ⚠ No models found. Run: ollama pull mistral:7b-instruct")
    else:
        print(f"  ✗ Ollama server is NOT running")
        print(f"  ℹ Start Ollama with: ollama serve")
except Exception as e:
    print(f"  ✗ Error checking Ollama: {e}")

# Check files
print("\n📄 Checking required files...")
required_files = [
    "src/ollama_client.py",
    "src/persona.py",
    "src/mitre_mapper.py",
    "src/mitre.json",
    "ui/app.py",
    "config/settings.yaml",
]

for file in required_files:
    if os.path.exists(file):
        print(f"  ✓ {file}")
    else:
        print(f"  ✗ {file} - MISSING")

# Test a simple query
print("\n🧪 Testing a simple query...")
try:
    from src.ollama_client import ollama_query
    test_response = ollama_query("Say 'Hello' in one word only.")
    if test_response and "Error" not in test_response:
        print(f"  ✓ Query successful")
        print(f"  Response: {test_response[:100]}")
    else:
        print(f"  ✗ Query failed: {test_response}")
except Exception as e:
    print(f"  ✗ Query error: {e}")

print("\n" + "=" * 60)
print("Diagnostic complete!")
print("=" * 60)
