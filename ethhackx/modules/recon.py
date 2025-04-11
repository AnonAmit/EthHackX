# Reconnaissance Module
from rich.console import Console
import questionary
import logging

from ..core import cli, executor, storage # Relative imports for core components

# Get logger
log = logging.getLogger(__name__)
console = Console()

def run_reconnaissance(target):
    """Main function for the Reconnaissance module."""
    log.info(f"Starting Reconnaissance module for target: {target}")
    console.print(f"\n[bold green]Initiating Reconnaissance Module for: {target}[/bold green]")

    while True:
        recon_type = cli.recon_menu() # Use the menu from core.cli

        if recon_type == "back":
            break
        try:
            if recon_type == "passive":
                run_passive_recon(target)
            elif recon_type == "active":
                run_active_recon(target)
            elif recon_type == "osint":
                run_osint_recon(target)
            # No need for explicit else for unimplemented, handled by cli menu return
        except Exception as e:
            log.exception(f"Error during {recon_type} reconnaissance for {target}")
            console.print(f"[bold red]An unexpected error occurred in {recon_type} recon: {e}[/bold red]")
            input("[yellow]Press Enter to continue...[/yellow]")

    log.info(f"Exiting Reconnaissance module for target: {target}")

# --- Passive Reconnaissance --- #
def run_passive_recon(target):
    log.info(f"Starting Passive Reconnaissance for {target}")
    console.print(f"\n[cyan]-- Passive Reconnaissance for {target} --[/cyan]")
    passive_choices = [
        questionary.Choice("Subdomain Enumeration (Subfinder)", value="subfinder"),
        questionary.Choice("WHOIS Lookup", value="whois"),
        questionary.Choice("DNS Records (dig/nslookup)", value="dns"), # Updated text
        questionary.Separator(),
        questionary.Choice("Run All Passive", value="all_passive"),
        questionary.Choice("Back", value="back")
    ]
    action = questionary.select("Choose Passive Recon Task:", choices=passive_choices).ask()

    if action == "back" or action is None:
        log.info("Returning from Passive Recon menu.")
        return

    results = {}
    tasks_to_run = []
    if action == "all_passive":
        tasks_to_run = ["subfinder", "whois", "dns"]
    else:
        tasks_to_run.append(action)

    for task in tasks_to_run:
        task_result = None
        log.info(f"Running passive task: {task}")
        try:
            if task == "subfinder":
                task_result = run_subfinder(target)
                if task_result: results.update({"subdomains": task_result})
            elif task == "whois":
                task_result = run_whois(target)
                if task_result: results.update({"whois": task_result})
            elif task == "dns":
                task_result = run_dns_lookup(target)
                if task_result: results.update({"dns": task_result})
        except Exception as e:
            log.exception(f"Error running passive task {task} for {target}")
            console.print(f"[bold red]Error during {task}: {e}[/bold red]")
            # Optionally ask to continue?
            # For now, continue to next task in 'all' mode

    if results:
        storage.save_results("recon_passive", target, results)
    else:
         log.info("No passive recon results generated to save.")

    console.print("[dim]Passive Reconnaissance tasks finished.[/dim]")
    input("Press Enter to continue...")

def run_subfinder(target):
    log.info(f"Running Subfinder for {target}")
    console.print("\n[+] Running Subdomain Enumeration (Subfinder)...")
    tool = "subfinder"
    if not executor.check_tool_installed(tool):
        console.print(f"[red]Error: {tool} not found. Please install it.[/red]")
        log.error(f"Subfinder tool not found.")
        return None

    command = [tool, "-d", target, "-silent"]
    stdout, stderr = executor.run_command(command)

    if stdout:
        subdomains = stdout.strip().split('\n')
        log.info(f"Subfinder found {len(subdomains)} subdomains for {target}")
        console.print(f"[green]Found {len(subdomains)} subdomains.[/green]")
        return subdomains
    else:
        log.warning(f"Subfinder returned no output for {target}. Stderr: {stderr}")
        console.print("[yellow]No subdomains found or error occurred.[/yellow]")
        if stderr: console.print(f"[red]Error details: {stderr}[/red]") # Keep user-facing stderr
        return None

def run_whois(target):
    log.info(f"Running WHOIS lookup for {target}")
    console.print("\n[+] Running WHOIS Lookup...")
    tool = "whois"
    has_library = False
    try:
        import whois as whois_lib # Alias to avoid conflict
        has_library = True
    except ImportError:
        log.debug("python-whois library not found.")
        pass # Library not available

    # Prefer library if available
    if has_library:
        log.info("Attempting WHOIS lookup via python-whois library.")
        console.print("[yellow]Using python-whois library.[/yellow]")
        try:
            w = whois_lib.whois(target)
            if not w.get('domain_name'): # Check if the result seems valid
                 log.warning(f"python-whois returned empty result for {target}. Raw: {w}")
                 console.print(f"[yellow]WHOIS library returned no domain data for {target}. Is it a valid domain?[/yellow]")
                 return None
            log.info(f"python-whois lookup successful for {target}")
            console.print("[green]WHOIS lookup successful.[/green]")
            # Extract key info reliably
            extracted_info = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "emails": w.emails,
                "status": w.status,
                "dnssec": w.dnssec,
                # Include raw text for completeness if available
                "raw": w.text if hasattr(w, 'text') else None
            }
            console.print(extracted_info) # Show summary to user
            return extracted_info
        except Exception as e:
            log.error(f"Error during python-whois lookup for {target}: {e}")
            console.print(f"[red]Error during python-whois lookup: {e}[/red]")
            # Don't return here, fallback to command if library failed?
            # For now, return None if library fails
            return None

    # Fallback to command if library not present or failed (optional based on above comment)
    log.info(f"Falling back to '{tool}' command for WHOIS lookup.")
    if not executor.check_tool_installed(tool):
        log.error(f"WHOIS failed: {tool} command not found and python-whois library not installed/failed.")
        console.print(f"[red]Error: {tool} command not found and python-whois library not available/failed.[/red]")
        return None

    command = [tool, target]
    stdout, stderr = executor.run_command(command)

    if stdout:
        log.info(f"WHOIS command lookup successful for {target}")
        console.print(f"[green]WHOIS command lookup successful.[/green]")
        # console.print(stdout)
        return {"raw_output": stdout}
    else:
        log.warning(f"WHOIS command failed or returned no data for {target}. Stderr: {stderr}")
        console.print("[yellow]WHOIS command lookup failed or returned no data.[/yellow]")
        if stderr: console.print(f"[red]Error details: {stderr}[/red]")
        return None

def run_dns_lookup(target):
    log.info(f"Running DNS lookup for {target}")
    console.print("\n[+] Running DNS Lookup...")
    tool = "dig"

    # Prioritize dig
    if executor.check_tool_installed(tool):
        command = [tool, "ANY", target, "+short"] # Get common records briefly
        stdout, stderr = executor.run_command(command)
        if stdout:
            records = stdout.strip().split('\n')
            log.info(f"DNS lookup (dig) successful for {target}. Found {len(records)} records.")
            console.print(f"[green]Found DNS records (using dig):[/green]")
            console.print(records)
            return {"tool": "dig", "records": records}
        else:
            log.warning(f"dig command failed or returned no data for {target}. Stderr: {stderr}")
            console.print(f"[yellow]dig command failed or returned no data for {target}.[/yellow]")
            # Don't return yet, try nslookup
    else:
         log.info("dig command not found, trying nslookup.")

    # Fallback to nslookup
    tool = "nslookup"
    if executor.check_tool_installed(tool):
        command = [tool, "-query=ANY", target]
        stdout, stderr = executor.run_command(command)
        if stdout:
             # Basic parsing for nslookup (can be fragile)
             records = [line.strip() for line in stdout.splitlines() if line.strip() and not line.startswith('Server:') and not line.startswith('Address:') and target not in line]
             log.info(f"DNS lookup (nslookup) successful for {target}. Found {len(records)} potential records.")
             console.print(f"[green]Found DNS records (using nslookup):[/green]")
             console.print(records)
             return {"tool": "nslookup", "records": records}
        else:
             log.warning(f"nslookup command failed or returned no data for {target}. Stderr: {stderr}")
             console.print(f"[yellow]nslookup command failed or returned no data for {target}.[/yellow]")
    else:
         log.error("DNS lookup failed: Neither dig nor nslookup found.")
         console.print("[red]Error: Neither dig nor nslookup found. Cannot perform DNS lookup.[/red]")

    return None # Return None if all methods fail

# --- Active Reconnaissance --- #
def run_active_recon(target):
    log.info(f"Starting Active Reconnaissance for {target}")
    console.print(f"\n[cyan]-- Active Reconnaissance for {target} --[/cyan]")

    if not executor.check_tool_installed("nmap"):
        log.error("Nmap command not found.")
        console.print("[red]Error: nmap command not found. Active scanning requires Nmap.[/red]")
        console.print("[yellow]Please install Nmap and ensure it's in your system's PATH.[/yellow]")
        input("Press Enter to continue...")
        return

    active_choices = [
        questionary.Choice("Quick Scan (Top 1000 TCP Ports)", value="nmap_quick"),
        questionary.Choice("Standard Scan (Includes Service Version)", value="nmap_standard"),
        questionary.Separator(),
        questionary.Choice("Back", value="back")
    ]
    action = questionary.select("Choose Active Recon Task:", choices=active_choices).ask()

    if action == "back" or action is None:
        log.info("Returning from Active Recon menu.")
        return

    results = None
    scan_type = "unknown"
    nmap_args = []

    if action == "nmap_quick":
        scan_type = "nmap_quick"
        nmap_args = ["-T4", "-F"]
    elif action == "nmap_standard":
        scan_type = "nmap_standard"
        nmap_args = ["-T4", "-sV", "-O"]
        console.print("[yellow]Standard scan includes OS (-O) and Service Version (-sV) detection, which may require root/administrator privileges.[/yellow]")

    if nmap_args:
        try:
            results = run_nmap_scan(target, scan_type, nmap_args)
        except Exception as e:
            log.exception(f"Error running nmap scan ({scan_type}) for {target}")
            console.print(f"[bold red]Error during Nmap scan: {e}[/bold red]")
            results = {"status": "error", "reason": str(e)} # Ensure results dict exists for saving

    if results:
        storage.save_results(f"recon_active_{scan_type}", target, results)
    else:
        log.info("No Nmap results generated to save.")

    console.print("[dim]Active Reconnaissance task finished.[/dim]")
    input("Press Enter to continue...")

def run_nmap_scan(target: str, scan_type: str, nmap_args: list):
    """Helper function to run nmap and capture output."""
    log.info(f"Running Nmap scan ({scan_type}) on {target} with args: {nmap_args}")
    console.print(f"\n[+] Running Nmap Scan ({scan_type}) on {target}...")
    console.print("[yellow]This may take some time depending on the scan type and target responsiveness.[/yellow]")

    command = ["nmap"] + nmap_args + [target]

    stdout, stderr = executor.run_command(command, capture_output=True)

    # Create result dict first
    result_data = {
         "status": "unknown",
         "output": stdout or "",
         "stderr": stderr or "",
         "command": " ".join(command)
    }

    if stderr and not stdout:
        # Check specific Nmap errors in stderr
        stderr_lower = stderr.lower()
        if "requires root privileges" in stderr_lower:
             reason = "requires root privileges"
             log.error(f"Nmap scan '{scan_type}' failed: {reason}")
             console.print(f"[bold red]Nmap requires root/administrator privileges for this scan type ({scan_type}). Try running EthHackX with sudo/admin rights.[/bold red]")
             result_data["status"] = "failed"
             result_data["reason"] = reason
             return result_data
        elif "illegal characters" in stderr_lower or "failed to resolve" in stderr_lower:
            reason = "invalid target/resolution failed"
            log.error(f"Nmap scan '{scan_type}' failed: {reason}")
            console.print(f"[bold red]Nmap failed to resolve target: {target}. Check the target format.[/bold red]")
            result_data["status"] = "failed"
            result_data["reason"] = reason
            return result_data
        else:
            log.warning(f"Nmap scan '{scan_type}' produced stderr but no stdout: {stderr.strip()}")
            console.print(f"[red]Nmap stderr output:\n{stderr.strip()}[/red]")
            result_data["status"] = "error" # Generic error if stderr present without known pattern
            return result_data

    if stdout:
        log.info(f"Nmap scan ({scan_type}) completed successfully for {target}")
        console.print(f"[green]Nmap scan ({scan_type}) completed.[/green]")
        console.print("--- Nmap Output --- (Saving full output to results file)")
        preview_lines = stdout.splitlines()[:15]
        console.print("\n".join(preview_lines))
        if len(stdout.splitlines()) > 15:
            console.print("... (output truncated in console) ...")
        console.print("--- End Nmap Output ---")
        result_data["status"] = "completed"
        return result_data
    else:
        # This case (no stdout, no known stderr error) might indicate other issues
        log.warning(f"Nmap scan ({scan_type}) did not return standard output. Stderr: {stderr.strip() if stderr else 'N/A'}")
        console.print(f"[yellow]Nmap scan ({scan_type}) did not return standard output, check logs/errors.[/yellow]")
        result_data["status"] = "no_output"
        return result_data

# --- OSINT Reconnaissance --- #
def run_osint_recon(target):
    log.info(f"Starting OSINT Reconnaissance for {target}")
    console.print(f"\n[cyan]-- OSINT Reconnaissance for {target} --[/cyan]")

    osint_choices = [
        questionary.Choice("Check Email Breaches (HaveIBeenPwned - requires API key/manual check)", value="hibp"),
        # questionary.Choice("Search Social Media (Placeholder)", value="social"),
        questionary.Choice("Generate Dorks (Uses Utility Module)", value="dorks"),
        questionary.Separator(),
        questionary.Choice("Back", value="back")
    ]
    action = questionary.select("Choose OSINT Task:", choices=osint_choices).ask()

    if action == "back" or action is None:
        log.info("Returning from OSINT Recon menu.")
        return

    if action == "hibp":
        log.warning("HIBP check requires manual intervention or API key integration.")
        console.print("[yellow]HaveIBeenPwned Check:[/yellow]")
        console.print(" - Please manually check relevant emails/domains at https://haveibeenpwned.com/")
        console.print(" - API integration requires an API key and careful handling.")
        # Placeholder result
        results = {"status": "manual_check_required", "service": "HaveIBeenPwned"}
        storage.save_results("recon_osint_hibp", target, results)

    # elif action == "social":
    #     log.warning("Social media search not implemented.")
    #     console.print("[yellow]Social Media search not implemented yet.[/yellow]")

    elif action == "dorks":
        # Call the dork generator utility directly
        # Requires importing utils_mod, maybe refactor dork generation?
        try:
            from ..modules import utils_mod # Lazy import
            # Decide whether to use target as domain or prompt
            use_target_as_domain = questionary.confirm(f"Use current target '{target}' as the domain for dorks?", default=True).ask()
            if use_target_as_domain:
                utils_mod.generate_domain_dorks(target)
            else:
                # Fallback to the standard dork generator prompt
                utils_mod.run_dork_generator()
            # No specific results to save here, dorks are printed
        except ImportError:
             log.error("Failed to import utils_mod for dork generation.")
             console.print("[red]Error: Could not load Utilities module for dork generation.[/red]")
        except Exception as e:
             log.exception("Error running dork generator from OSINT module.")
             console.print(f"[red]Error generating dorks: {e}[/red]")

    console.print("[dim]OSINT Reconnaissance task finished.[/dim]")
    input("Press Enter to continue...") 