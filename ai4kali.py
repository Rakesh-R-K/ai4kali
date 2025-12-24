#!/usr/bin/env python3
"""
AI4Kali (LLM-only, fast, creative TUI)
- Generates a single terminal command from natural language using local Ollama.
- Supports --dry-run, --explain, --tui, --yes, --model, --timeout, --debug.
- Creative TUI built using rich (no heavy deps).
- Safety checks to avoid obviously destructive commands.

Usage examples:
  ai4kali "scan this host and find what's running"
  ai4kali --dry-run "scan 10.10.10.10 for open ports"
  ai4kali --explain "nmap -sV 10.10.10.10"
  ai4kali --tui
"""

import argparse
import subprocess
import sys
import time
import re
import shlex
from shutil import which
from typing import Optional, Tuple, List

# Try import rich for TUI and pretty output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.live import Live
    from rich.text import Text
    from rich.spinner import Spinner
    from rich.align import Align
    from rich.layout import Layout
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    # fallback console prints
    console = None

# ---------- Config ----------
DEFAULT_MODEL_CANDIDATES = ["phi", "llama3.2", "mistral", "gemma:2b"]
OLLAMA_BIN = "ollama"
DEFAULT_TIMEOUT = 20
DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\b", r"\bdd\s+if=", r"\bmkfs\b", r":\s*\(\)\s*\{", r"\bshutdown\b",
    r"\breboot\b", r"wget\s+.*\|\s*sh", r"curl\s+.*\|\s*sh", r">/dev/sd", r"fdisk\b",
    r"chmod\s+0{1,3}\b", r"chown\s+root\b", r"\bformat\b"
]
SAFE_TOOL_PREFIXES = [
    "nmap","curl","wget","ping","ss","netstat","tcpdump","tshark","hydra","medusa",
    "john","nikto","gobuster","ffuf","dirb","dirsearch","nc","ncat","ssh","scp",
    "rsync","systemctl","journalctl","cat","less","grep","awk","sed","whoami","uname"
]

# ---------- Helpers ----------
def has_ollama() -> bool:
    return which(OLLAMA_BIN) is not None

def run_subprocess(cmd: list, timeout: int = 30) -> Tuple[int, str, str]:
    """Run subprocess, return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode(errors="ignore")
        err = proc.stderr.decode(errors="ignore")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except FileNotFoundError:
        return 127, "", "NOT_FOUND"
    except Exception as e:
        return 1, "", str(e)

def detect_best_model(preferred: Optional[str] = None) -> Optional[str]:
    """If user passed --model it's honored; otherwise try to pick a model that exists."""
    if not has_ollama():
        return None
    # ask ollama list
    rc, out, err = run_subprocess([OLLAMA_BIN, "list"], timeout=5)
    models_text = out.lower() if out else ""
    # if preferred specified and present, use it
    if preferred:
        if preferred.lower() in models_text:
            return preferred
        # try with :latest suffix if user used "llama3.2"
        if f"{preferred.lower()}:latest" in models_text:
            return preferred
    # pick first candidate that appears in ollama list
    for m in DEFAULT_MODEL_CANDIDATES:
        if m.lower() in models_text:
            return m
        if f"{m.lower()}:latest" in models_text:
            return m
    # as final fallback, parse any model name from ollama list output (first token)
    if models_text:
        # parse lines like "mistral:latest 2.0GB"
        first_line = models_text.splitlines()[0].strip()
        candidate = first_line.split()[0]
        if candidate:
            return candidate
    return None

def call_ollama_run(model: str, prompt: str, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    """Call ollama run <model> and return (stdout, error)."""
    try:
        proc = subprocess.run([OLLAMA_BIN, "run", model], input=prompt.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode(errors="ignore").strip()
        err = proc.stderr.decode(errors="ignore").strip()
        if proc.returncode != 0 and not out:
            return None, err or f"exit:{proc.returncode}"
        return out, None
    except subprocess.TimeoutExpired:
        return None, "OLLAMA_TIMEOUT"
    except FileNotFoundError:
        return None, "OLLAMA_NOT_FOUND"
    except Exception as e:
        return None, str(e)

# ---------- Safety checks ----------
def is_dangerous(cmd: str) -> bool:
    s = cmd.lower()
    for p in DANGEROUS_PATTERNS:
        if re.search(p, s):
            return True
    return False

def looks_like_command(cmd: str) -> bool:
    if not cmd or len(cmd.strip()) < 2:
        return False
    first = cmd.strip().split()[0].lower()
    if first == "sudo":
        parts = cmd.strip().split()
        if len(parts) > 1:
            first = parts[1].lower()
    # allow simple builtins
    if first in ("echo","ls","ps","top","htop","whoami","uname"):
        return True
    return any(first.startswith(prefix) for prefix in SAFE_TOOL_PREFIXES)

# ---------- Prompt templates ----------
PROMPT_SINGLE_COMMAND = """You are a concise Kali Linux assistant. The user request:
{query}

Return EXACTLY one terminal command (single line) that performs this task. Do NOT output explanations, markdown, or other text.
If the request is ambiguous or unsafe, output: echo "no-command"
"""

PROMPT_EXPLAIN = """You are an expert Linux instructor. Explain in clear, short bullet points what the following command does and any safety considerations:

{cmd}

Keep it brief (max 10 lines).
"""

# ---------- Core flows ----------
def generate_command(query: str, model: str, timeout: int = DEFAULT_TIMEOUT, debug: bool = False) -> Tuple[Optional[str], Optional[str]]:
    prompt = PROMPT_SINGLE_COMMAND.format(query=query)
    if debug and RICH_AVAILABLE:
        console.log("[debug] Prompt sent to model:", prompt)
    out, err = call_ollama_run(model, prompt, timeout)
    if err:
        return None, err
    # prefer first non-empty line
    for ln in out.splitlines():
        ln = ln.strip()
        if ln:
            return ln, None
    return None, "empty_response"

def explain_with_model(cmd: str, model: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[Optional[str], Optional[str]]:
    prompt = PROMPT_EXPLAIN.format(cmd=cmd)
    return call_ollama_run(model, prompt, timeout)

def execute_command(cmd: str) -> int:
    """Execute command using shell to allow pipes. Returns rc."""
    try:
        rc = subprocess.call(cmd, shell=True)
        return rc
    except Exception as e:
        print("Execution error:", e)
        return 1

# ---------- Minimal creative TUI using rich ----------
def run_rich_tui(default_model: str, timeout: int):
    if not RICH_AVAILABLE:
        print("TUI requires the 'rich' package. Install with: python3 -m pip install --user rich")
        return

    welcome = Text()
    welcome.append("⚡ ", style="bold magenta")
    welcome.append("AI4KALI", style="bold cyan")
    welcome.append(" — Local LLM Command Assistant\n\n", style="bold white")
    welcome.append("Type your task in the input prompt below, or press Ctrl+C to quit.\n", style="dim")

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(Layout(name="left"), Layout(name="right", ratio=2))

    layout["header"].update(Panel(welcome, style="on #0b1220"))
    layout["left"].update(Panel("📚 Context\n(cheats & man available via --explain mode)\n", title="Context", border_style="blue"))
    layout["right"].update(Panel("Ready.", title="Generated Command", border_style="green"))
    layout["footer"].update(Panel("[Enter] Generate  |  [E] Explain  |  [R] Run  |  [D] Dry-run  |  [Q] Quit", style="bold"))

    console.clear()
    console.print(layout)

    try:
        while True:
            query = Prompt.ask("\n[bold cyan]Describe the task[/]").strip()
            if not query:
                console.print("[dim]No input, try again.[/]")
                continue

            # show spinner while generating
            with Live(Spinner("dots", text=" Generating command using LLM..."), refresh_per_second=12, transient=True):
                generated, err = generate_command(query, default_model, timeout=timeout, debug=False)
                time.sleep(0.05)
            if err:
                console.print(Panel(f"[red]Model error:[/]\n{err}", title="Error"))
                continue
            # display the generated command
            layout["right"].update(Panel(Text(generated, style="bold green"), title="Generated Command", border_style="green"))
            console.print(layout)

            # small interactive loop
            while True:
                action = Prompt.ask("\nChoose action: [g]enerate again / [e]explain / [r]run / [d]dry-run / [q]quit", choices=["g","e","r","d","q"], default="g")
                if action == "g":
                    break  # go back to getting new query
                elif action == "e":
                    out, err = explain_with_model(generated, default_model, timeout=timeout)
                    if err:
                        console.print(Panel(f"[red]Error explaining:[/]\n{err}"))
                    else:
                        console.print(Panel(Markdown(out or "No explanation produced."), title="Explanation", border_style="magenta"))
                    # after showing, loop to action selection
                elif action == "r":
                    if is_dangerous(generated):
                        console.print(Panel("[red]Command flagged as dangerous — will not execute.[/]", title="Safety"))
                        continue
                    confirm = Prompt.ask(f"Run the command [bold]{generated}[/]? (y/n)", choices=["y","n"], default="n")
                    if confirm == "y":
                        console.print(Panel("[yellow]Executing...[/]"))
                        rc = execute_command(generated)
                        console.print(Panel(f"Command finished with exit code: {rc}"))
                    else:
                        console.print("Cancelled.")
                elif action == "d":
                    console.print(Panel(f"[cyan]DRY RUN — Command generated (not executed):[/]\n\n{generated}"))
                elif action == "q":
                    console.print("Goodbye.")
                    return
    except KeyboardInterrupt:
        console.print("\nExiting TUI. Bye.")
        return

# ---------- Simple interactive fallback (non-TUI) ----------
def run_simple_cli(default_model: str, timeout: int, args):
    print("\nAI4KALI — simple interactive mode (no rich)")
    print("Type your task, or blank to quit.")
    while True:
        try:
            query = input("\nTask > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            return
        if not query:
            print("Goodbye.")
            return
        # generate command
        print("Generating command...")
        generated, err = generate_command(query, default_model, timeout=timeout, debug=args.debug)
        if err:
            print("Model error:", err)
            continue
        print("\nGenerated command:\n", generated)
        if args.dry_run:
            print("\n(dry-run) not executing.")
            continue
        if args.explain:
            out, err = explain_with_model(generated, default_model, timeout=timeout)
            if out:
                print("\nExplanation:\n", out)
        run = "y" if args.yes else input("\nRun this command? (y/n) ").strip().lower()
        if run in ("y","yes"):
            if is_dangerous(generated):
                print("Command flagged as dangerous. Not executing.")
                continue
            rc = execute_command(generated)
            print("Exit code:", rc)
        else:
            print("Cancelled.")

# ---------- CLI entry ----------
def main():
    parser = argparse.ArgumentParser(description="AI4Kali - LLM-only command assistant (fast, local)")
    parser.add_argument("query", nargs="*", help="Natural language query. If omitted and --tui not used, prompts interactively.")
    parser.add_argument("--model", help="Specify Ollama model name (optional).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Model timeout seconds")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run", help="Generate but do not execute")
    parser.add_argument("--explain", action="store_true", help="Ask the model to explain the generated command (after generation)")
    parser.add_argument("--tui", action="store_true", help="Launch creative TUI (rich required)")
    parser.add_argument("--yes", action="store_true", help="Auto-confirm execution")
    parser.add_argument("--debug", action="store_true", help="Show debug info")
    args = parser.parse_args()

    if not has_ollama():
        msg = "ollama CLI not found in PATH. Install ollama and pull a model (e.g. `ollama pull phi`)."
        if RICH_AVAILABLE:
            console.print(Panel(msg, title="Error", style="red"))
        else:
            print(msg)
        sys.exit(1)

    default_model = detect_best_model(args.model)
    if not default_model:
        if RICH_AVAILABLE:
            console.print(Panel("No Ollama model detected. Run `ollama pull phi` or `ollama list`.", title="Error", style="red"))
        else:
            print("No Ollama model detected. Run `ollama pull phi` or `ollama list`.")
        sys.exit(1)

    if args.debug and RICH_AVAILABLE:
        console.log(f"[debug] selected model: {default_model}")

    # If TUI requested, launch it
    if args.tui:
        run_rich_tui(default_model, timeout=args.timeout)
        return

    # If no query and not TUI, run interactive simple CLI
    if not args.query:
        run_simple_cli(default_model, timeout=args.timeout, args=args)
        return

    # Non-interactive single-shot mode: generate -> optionally explain -> confirm -> execute
    query = " ".join(args.query).strip()
    if not query:
        print("Empty query.")
        return

    if RICH_AVAILABLE:
        console.print(Panel(f"Generating command for: [bold]{query}[/]\n(model: {default_model})", style="cyan"))
    else:
        print(f"Generating command for: {query} (model: {default_model})")

    gen, err = generate_command(query, default_model, timeout=args.timeout, debug=args.debug)
    if err:
        if RICH_AVAILABLE:
            console.print(Panel(f"[red]Model error:[/]\n{err}"))
        else:
            print("Model error:", err)
        sys.exit(1)
    if gen is None:
        print("Model returned no command.")
        sys.exit(1)

    # take only first line
    candidate = gen.strip().splitlines()[0]

    if candidate == 'echo "no-command"':
        print("Model refused to provide a command for safety/ambiguity.")
        return

    if not looks_like_command(candidate):
        print("Model output doesn't look like a valid command. Output:")
        print(candidate)
        return
    if is_dangerous(candidate):
        print("Command flagged as dangerous. Will not execute.")
        print(candidate)
        return

    # Present to user
    if RICH_AVAILABLE:
        console.print(Panel(Text(candidate, style="bold green"), title="Generated Command"))
    else:
        print("\nGenerated Command:\n", candidate)

    if args.dry_run:
        if RICH_AVAILABLE:
            console.print(Panel("[cyan]DRY RUN — not executing[/]"))
        else:
            print("(dry-run) not executing")
        if args.explain:
            out, err = explain_with_model(candidate, default_model, timeout=args.timeout)
            if out:
                print("\nExplanation:\n", out)
        return

    if args.explain:
        out, err = explain_with_model(candidate, default_model, timeout=args.timeout)
        if err:
            print("Explain error:", err)
        else:
            if RICH_AVAILABLE:
                console.print(Panel(Markdown(out or "No explanation produced."), title="Explanation", border_style="magenta"))
            else:
                print("\nExplanation:\n", out)

    if args.yes:
        confirmed = "y"
    else:
        try:
            confirmed = input("\nRun this command? (y/n) ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return

    if confirmed not in ("y", "yes"):
        print("Cancelled.")
        return

    # final safety re-check
    if is_dangerous(candidate):
        print("Blocked: command considered dangerous.")
        return

    # execute
    print("\nExecuting...\n")
    rc = execute_command(candidate)
    print("\nExit code:", rc)

if __name__ == "__main__":
    main()
