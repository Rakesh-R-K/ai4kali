# //The raw code for ai4kali 
#!/usr/bin/env python3

import subprocess
import json
import sys

MODEL = "llama3.2" # Cause this model works better ......!!
OLLAMA_URL = "http://localhost:11434/api/generate"

SYSTEM_PROMPT = """
You are an expert Kali Linux penetration tester.
Convert the user's request into a single correct Kali Linux command.
Rules:
- Output ONLY the command
- No explanations
- No markdown
- No backticks
- No comments
"""

def generate_command(user_input):
    payload = {
        "model": MODEL,
        "prompt": f"{SYSTEM_PROMPT}\nUser request: {user_input}",
        "stream": False
    }

    try:
        result = subprocess.run(
            ["curl", "-s", "-X", "POST", OLLAMA_URL, "-d", json.dumps(payload)],
            capture_output=True,
            text=True
        )
        response = json.loads(result.stdout)
        return response["response"].strip()
    except Exception as e:
        print("[-] LLM error:", e)
        sys.exit(1)

def main():
    print("\n🧠 ai4kali — LLM Command Generator\n")

    user_input = input("💬 What do you want to do? → ").strip()
    if not user_input:
        print("[-] Empty input")
        return

    command = generate_command(user_input)

    print("\n⚡ Generated Command:")
    print(f"\n{command}\n")

    choice = input("▶ Execute this command? [y/N]: ").strip().lower()
    if choice == "y":
        print("\n🚀 Executing...\n")
        subprocess.run(command, shell=True)
    else:
        print("❌ Execution cancelled.")

if __name__ == "__main__":
    main()
