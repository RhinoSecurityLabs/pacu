"""Colored console output for Pacu using rich.

Falls back to plain print() if rich is not installed so that
existing behavior is preserved in minimal environments.
"""

try:
    from rich.console import Console
    from rich.theme import Theme
    from rich.panel import Panel

    _PACU_THEME = Theme({
        "banner": "bold cyan",
        "info": "bold blue",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "module.name": "bold magenta",
        "prompt.session": "bold green",
        "prompt.keys": "bold yellow",
    })

    console = Console(theme=_PACU_THEME, highlight=False)
    RICH_AVAILABLE = True

except ImportError:
    console = None  # type: ignore[assignment]
    RICH_AVAILABLE = False


# -- helper functions used by main.py --

def print_banner(text: str, version: str) -> None:
    """Print the Pacu ASCII art banner with color."""
    if RICH_AVAILABLE:
        console.print(text, style="banner")
        console.print(f"Version: {version}", style="info")
    else:
        print(text)
        print(f"Version: {version}")


def print_success(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[success]{message}[/success]")
    else:
        print(message)


def print_error(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[error]{message}[/error]")
    else:
        print(message)


def print_warning(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[warning]{message}[/warning]")
    else:
        print(message)


def print_info(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[info]{message}[/info]")
    else:
        print(message)


def print_module_summary(module_name: str, summary: str) -> None:
    """Print a module completion summary inside a panel."""
    if RICH_AVAILABLE:
        console.print(f"[success]{module_name} completed.[/success]\n")
        console.print(Panel(summary.strip("\n"), title="Module Summary", border_style="green"))
    else:
        print(f"{module_name} completed.\n")
        print(f"MODULE SUMMARY:\n\n{summary.strip(chr(10))}\n")


def build_prompt(session_name: str, alias: str) -> str:
    """Return the interactive prompt string, colored if rich is available."""
    if RICH_AVAILABLE:
        # ANSI escape codes directly in the prompt string so readline
        # can measure visible length correctly (rich markup would break
        # readline's line-length calculation).
        green = "\001\033[1;32m\002"
        yellow = "\001\033[1;33m\002"
        reset = "\001\033[0m\002"
        return f"{green}Pacu{reset} ({green}{session_name}{reset}:{yellow}{alias}{reset}) > "
    else:
        return f"Pacu ({session_name}:{alias}) > "
