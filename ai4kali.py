#!/usr/bin/env python3
import subprocess
import sys
import re
import requests
import json

MODEL = "llama3.2"   # change it to the model u need

DANGEROUS_PATTERNS = [
    r"rm -rf /", r"rm -rf \*", r"mkfs", r"dd if=", r":\(\)\s*{\s*\:\|\:\&\}\;\:",
    r"shutdown", r"reboot", r"halt", r"init 0", r"init 6",
    r"wipefs", r"fdisk", r"mklabel", r"mkpart", r"chmod 777 /",
]

def is_dangerous(cmd):
    """Return True if command matches any dangerous pattern."""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return True
    return False

def ask_ollama(query):
    prompt = f"""
You are a Kali Linux expert.
Translate the following request into ONE safe Linux command.
Do NOT add explanations. Do NOT add quotes.

Request:
{query}
"""

    url = "http://localhost:11434/api/generate"
    data = {
        "model": MODEL,
        "prompt": prompt
    }

    response = requests.post(url, json=data, stream=True)

    full_response = ""
    for line in response.iter_lines():
        if line:
            msg = json.loads(line.decode("utf-8"))
            if "response" in msg:
                full_response += msg["response"]

    return full_response.strip()

def main():
    if len(sys.argv) < 2:
        print("Usage: ai4kali <natural language request>")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    command = ask_ollama(query)

    print("\n🔹 Generated Command:")
    print(f"   {command}\n")

    # Safety check
    if is_dangerous(command):
        print("WARNING: This command is potentially dangerous and will NOT be executed.")
        sys.exit(0)

    choice = input("Run this command? (y/n): ").lower()
    if choice == "y":
        print("\n Executing...\n")
        subprocess.run(command, shell=True)
    else:
        print("Cancelled.")

if __name__ == "__main__":
    main()
