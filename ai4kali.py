#!/usr/bin/env python3

import subprocess
import argparse
import sys
import re

DEFAULT_MODEL = "llama3.2"
TIMEOUT = 20            
OLLAMA_BIN = "ollama"

DANGEROUS = [
    r"rm\s+-rf", r"dd\s+", r"mkfs", r":\s*\(\)\s*\{", r"shutdown", r"reboot",
    r"wget\s+.*\|\s*sh", r"curl\s+.*\|\s*sh"
]

SAFE_TOOLS = [
    "nmap","curl","wget","ping","ss","netstat","tshark","tcpdump",
    "hydra","medusa","gobuster","ffuf","nikto","enum4linux","smbmap",
    "searchsploit","msfconsole","dirb","dirsearch","nc","ncat","ssh"
]

PROMPT = """
You are a Kali Linux command generator.
The user request is:

"{query}"

Return EXACTLY ONE valid Linux command that performs this task.
Do NOT include explanations, markdown, or extra text.
If the request is unclear or unsafe, return: echo "no-command"
"""

def run_model(model, prompt):
    """Call Ollama and return model output or None."""
    try:
        proc = subprocess.run(
            [OLLAMA_BIN, "run", model],
            input=prompt.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT
        )
        out = proc.stdout.decode().strip()
        err = proc.stderr.decode().strip()

        if proc.returncode != 0:
            return None

        return out
    except:
        return None


def looks_safe(cmd):
    """Check for dangerous patterns."""
    for p in DANGEROUS:
        if re.search(p, cmd, re.IGNORECASE):
            return False
    return True


def looks_like_command(cmd):
    """Check if the first token appears to be a real tool."""
    parts = cmd.split()
    if not parts:
        return False
    first = parts[0].lower()

    # allow sudo prefix
    if first == "sudo" and len(parts) > 1:
        first = parts[1].lower()

    return first in SAFE_TOOLS


def main():
    parser = argparse.ArgumentParser(description="AI4Kali LLM Command Generator")
    parser.add_argument("query", nargs="+", help="Natural language request")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("--yes", action="store_true", help="Run without asking")
    parser.add_argument("--dry", action="store_true", help="Show command but do not run")

    args = parser.parse_args()
    query = " ".join(args.query).strip()

    prompt = PROMPT.format(query=query)
    result = run_model(args.model, prompt)

    if not result:
        print("Model failed.")
        sys.exit(1)

    # take first non-empty line as command
    lines = [l.strip() for l in result.splitlines() if l.strip()]
    if not lines:
        print("Model returned nothing.")
        sys.exit(1)

    cmd = lines[0]

    if cmd == 'echo "no-command"':
        print("Request was unclear or unsafe. No command generated.")
        sys.exit(0)

    # validate
    if not looks_safe(cmd):
        print("Command flagged as dangerous:", cmd)
        sys.exit(1)

    if not looks_like_command(cmd):
        print("Output does not resemble a valid Kali command:")
        print(cmd)
        sys.exit(1)

    print("\n Generated Command:\n")
    print(cmd)

    if args.dry:
        print("\n(dry-run mode)")
        sys.exit(0)

    if not args.yes:
        run = input("\nRun this command? (y/n): ").lower().strip()
        if run not in ("y", "yes"):
            print("Cancelled.")
            sys.exit(0)

    print("\n▶ Executing...\n")
    rc = subprocess.call(cmd, shell=True)
    print("\nExit code:", rc)


if __name__ == "__main__":
    main()
