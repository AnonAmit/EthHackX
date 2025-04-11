import questionary
from rich.console import Console
from rich.panel import Panel
import pyfiglet
import sys

console = Console()

def display_banner():
    """Displays the EthHackX ASCII art banner."""
    # You can choose different fonts from pyfiglet
    try:
        ascii_banner = pyfiglet.figlet_format("EthHackX", font="slant") # Or try: standard, banner, doom, etc.
        console.print(f"[bold magenta]{ascii_banner}[/bold magenta]")
        console.print(Panel("[cyan]The Interactive Ethical Hacking Framework[/cyan]",
                          title="🔥 Welcome 🔥", subtitle="v0.1.0", border_style="bold green"))
    except pyfiglet.FontNotFound:
        console.print("[bold magenta]EthHackX[/bold magenta] - [cyan]The Interactive Ethical Hacking Framework[/cyan]")
        console.print("[yellow]Warning: pyfiglet font 'slant' not found. Using default text.[/yellow]")

def get_target(last_target=None):
    """Prompts the user to enter the target domain or IP."""
    default_value = last_target if last_target else ""
    target = questionary.text(
        "Enter the target domain or IP:",
        default=default_value,
        validate=lambda text: True if len(text) > 0 else "Target cannot be empty."
    ).ask()
    if target is None: # Handle Ctrl+C
        exit_app()
    return target

def main_menu():
    """Displays the main menu and returns the selected action key."""
    choices = [
        questionary.Choice(title="Reconnaissance", value="recon"),
        questionary.Choice(title="Vulnerability Scanning", value="scan"),
        questionary.Choice(title="Exploitation", value="exploit"),
        questionary.Choice(title="Post Exploitation", value="post_exploit"),
        questionary.Choice(title="Auto Attack (Full Workflow)", value="auto"),
        questionary.Choice(title="Utilities", value="utils"),
        questionary.Choice(title="Generate Final Report", value="report"),
        questionary.Separator(),
        questionary.Choice(title="Exit", value="exit")
    ]

    action = questionary.select(
        "Choose an action:",
        choices=choices,
        use_shortcuts=True,
        style=questionary.Style([('highlighted', 'fg:#673ab7 bold'), ('selected', 'fg:white bg:#673ab7')]) # Example style
    ).ask()

    if action is None: # Handle Ctrl+C
        return "exit"
    return action

def exit_app():
    """Prints a goodbye message and exits."""
    console.print("\n[bold green]Exiting EthHackX. Happy Hacking![/bold green]")
    sys.exit(0)

# --- Placeholder Menus for Modules (to be expanded) ---

def recon_menu():
    """Displays the reconnaissance module menu."""
    choices = [
        questionary.Choice(title="Passive Recon (WHOIS, Subdomains, DNS)", value="passive"),
        questionary.Choice(title="Active Recon (Port Scan, Banner Grab)", value="active"),
        questionary.Choice(title="OSINT Recon (Emails, Dorks)", value="osint"),
        questionary.Separator(),
        questionary.Choice(title="Back", value="back")
    ]
    action = questionary.select("[RECON MODULE] Choose Recon Type:", choices=choices).ask()
    if action is None: return "back"
    return action

def scan_menu():
    """Displays the vulnerability scanning module menu."""
    choices = [
        questionary.Choice(title="Web Server Scan (Nikto)", value="nikto"),
        questionary.Choice(title="CVE/Misconfig Scan (Nuclei)", value="nuclei"),
        questionary.Choice(title="SSL/TLS Scan (SSLScan)", value="sslscan"),
        questionary.Choice(title="WordPress Scan (WPScan)", value="wpscan"),
        questionary.Separator(),
        questionary.Choice(title="Back", value="back")
    ]
    action = questionary.select("[SCAN MODULE] Choose Scan Type:", choices=choices).ask()
    if action is None: return "back"
    return action

def utils_menu():
    """Displays the utilities module menu."""
    choices = [
        questionary.Choice(title="Hash Identifier", value="hash_id"),
        questionary.Choice(title="Payload Encoder (Base64, Hex, URL)", value="encoder"),
        questionary.Choice(title="Dork Generator (Google, GitHub)", value="dorker"),
        questionary.Choice(title="IP Geolocation Lookup", value="geoip"),
        questionary.Separator(),
        questionary.Choice(title="Back", value="back")
    ]
    action = questionary.select("[UTILITIES MODULE] Choose Utility:", choices=choices).ask()
    if action is None: return "back"
    return action

# Placeholder for Report Menu
def report_menu():
     """Displays the report generation menu."""
     choices = [
        questionary.Choice(title="Generate Markdown Report", value="markdown"),
        questionary.Choice(title="Generate JSON Summary", value="json"),
        # questionary.Choice(title="Export to HTML (Requires Pandoc?)", value="html"),
        questionary.Separator(),
        questionary.Choice(title="Back", value="back")
    ]
     action = questionary.select("[REPORT MODULE] Choose Action:", choices=choices).ask()
     if action is None: return "back"
     return action

# Add similar placeholder menus for exploit, post_exploit, utils_mod, report if needed 