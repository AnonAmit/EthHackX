# Auto Attack module
from rich.console import Console
from rich.panel import Panel
import questionary
import logging
from rich.table import Table

# Import module functions directly for clarity
from . import recon
from . import scan
from . import exploit # Keep import for potential future use
from . import report
from ..core import storage # Needed?
from ..core import cli, config # Import necessary core components

log = logging.getLogger(__name__) # Setup logger
console = Console()

def run_auto_attack(target, headless=False):
    """Runs a predefined sequence of modules against the target."""
    log.info(f"Starting Auto Attack sequence for target: {target} (Headless: {headless})")
    console.print(Panel(f"[bold yellow]Starting Auto Attack Sequence for: {target}[/bold yellow]",
                      title="🛡️ Auto Attack Mode 🛡️", expand=False, border_style="red"))

    # Define the sequence
    # Structure: (step_name, function_to_call, step_args_or_tuple)
    sequence = [
        # --- Reconnaissance --- #
        ("Recon - Passive (Subfinder)", recon.run_subfinder, target),
        ("Recon - Passive (WHOIS)", recon.run_whois, target),
        ("Recon - Passive (DNS Lookup)", recon.run_dns_lookup, target),
        ("Recon - Active (Nmap Quick Scan)", recon.run_nmap_scan, (target, "nmap_quick_auto", ["-T4", "-F"])), # Args as tuple
        # --- Scanning --- #
        ("Scan - Web Server (Nikto)", scan.run_nikto_scan, target),
        ("Scan - Templates (Nuclei)", scan.run_nuclei_scan, target),
        ("Scan - SSL/TLS (SSLScan)", scan.run_ssl_scan, target),
        # TODO: Add WPScan check conditionally? Needs target check before running.
        # TODO: Add basic exploit checks?
        # --- Reporting --- #
        ("Report - Generate Markdown", generate_auto_report, target), # Use a wrapper for report generation
    ]

    total_steps = len(sequence)
    console.print(f"Sequence includes {total_steps} steps.")

    # Skip confirmation in headless mode
    confirm = True
    if not headless:
        confirm = questionary.confirm("Proceed with Auto Attack? (This may take a long time and be intrusive)", default=False).ask()

    if confirm is None or not confirm: # Handle Ctrl+C or No
        log.info("User cancelled Auto Attack sequence.")
        console.print("[yellow]Auto Attack cancelled.[/yellow]")
        return

    console.print("\n[bold]Starting sequence...[/bold]")
    all_results_summary = [] # Store brief status of each step

    for i, (step_name, step_func, step_args) in enumerate(sequence):
        console.rule(f"[bold cyan]Step {i+1}/{total_steps}: {step_name}[/bold cyan]")
        try:
            # Handle single arg vs tuple of args for the step function
            if isinstance(step_args, tuple):
                result = step_func(*step_args) # Unpack tuple arguments
            else:
                result = step_func(step_args) # Pass single argument

            # Determine step status based on return value (can be refined)
            status = "Completed" # Default assumption
            if result is None:
                status = "Completed (No specific return)"
            elif isinstance(result, dict):
                if result.get("status") == "failed":
                    status = f"Failed ({result.get('reason', 'Unknown reason')})"
                elif result.get("status") == "error":
                    status = f"Error ({result.get('stderr', 'Unknown error')[:60]}...)"
                elif result.get("status") == "skipped":
                    status = f"Skipped ({result.get('reason', 'No reason specified')})"
                # Add more specific status checks if module functions return them

            all_results_summary.append({"step": step_name, "status": status})
            console.print(f"[green]Finished: {step_name} - Status: {status}[/green]")

        except NotImplementedError:
            log.warning(f"Auto Attack step '{step_name}' skipped: Function not implemented.")
            if not headless:
                 console.print("[yellow]Module/Function not implemented yet. Skipping.[/yellow]")
            all_results_summary.append({"step": step_name, "status": "Skipped (Not Implemented)"})

        except Exception as e:
            error_msg = str(e)
            log.exception(f"Error executing step '{step_name}': {error_msg}")
            # logger.log_exception(e) # TODO: Add proper logging
            all_results_summary.append({"step": step_name, "status": f"Runtime Error: {error_msg[:100]}..."})

            # Skip confirmation prompt in headless mode, just abort
            if headless:
                 console.print("[red]Auto Attack sequence aborted due to error in headless mode.[/red]")
                 raise e # Re-raise exception in headless mode to signal failure clearly
            else:
                proceed = questionary.confirm("An error occurred. Continue with the next step?", default=False).ask()
                if proceed is None or not proceed: # Handle Ctrl+C or No
                    console.print("[red]Auto Attack sequence aborted due to error.[/red]")
                    break # Stop the sequence
        console.print("") # Add a newline for spacing

    console.rule("[bold green]Auto Attack Sequence Finished[/bold green]")
    console.print("\nSummary of steps executed:")
    for item in all_results_summary:
        # Determine color based on status keyword
        status_lower = item["status"].lower()
        if "completed" in status_lower:
            color = "green"
        elif "skipped" in status_lower:
             color = "blue"
        elif "error" in status_lower or "failed" in status_lower:
            color = "red"
        else:
            color = "yellow" # Default for unexpected status

        console.print(f"- {item['step']}: [{color}]{item['status']}[/{color}]")

    # Skip final prompt in headless mode
    if not headless:
        input("\nPress Enter to return to the main menu...")

    log.info("Auto Attack sequence finished.")
    if not headless:
        console.print("\n[bold green]=== Auto Attack Sequence Finished ===[/bold green]")
        table = Table(title="Auto Attack Summary", show_header=True, header_style="bold magenta")
        table.add_column("Step", style="dim", width=30)
        table.add_column("Status", justify="right")

        for result in all_results_summary:
            status_style = "green" if result["status"] == "Completed" else "yellow" if "Skipped" in result["status"] else "red"
            table.add_row(result["step"], f"[{status_style}]{result['status']}[/{status_style}]")
        console.print(table)
    else:
        console.print("--- Auto Attack Summary ---")
        for result in all_results_summary:
             console.print(f"- {result['step']}: {result['status']}")
        console.print("-------------------------")

    overall_success = all(item["status"] == "Completed" for item in all_results_summary)
    if overall_success:
        log.info("Auto Attack completed successfully (all steps ran without critical errors).")
        if not headless:
            console.print("[bold green]Auto Attack completed successfully![/bold green]")
        else:
            console.print("Auto Attack finished.")
    else:
        log.warning("Auto Attack completed with one or more errors.")
        if not headless:
            console.print("[bold yellow]Auto Attack completed with errors. Please review logs and output.[/bold yellow]")
        else:
            console.print("Auto Attack finished with errors.")

    log.info(f"Exiting Auto Attack module for target: {target}")

def generate_auto_report(target):
    """Wrapper to automatically generate markdown report after auto attack."""
    console.print("\nAttempting to generate final Markdown report...")
    all_data = storage.load_all_results(target)
    if not all_data:
        console.print("[yellow]No result files found to generate report.[/yellow]")
        return {"status": "skipped", "reason": "No results found"}

    # Directly call the markdown generation function from the report module
    try:
        # Pass the loaded data directly
        report.generate_markdown_report(target, all_data)
        # We might want generate_markdown_report to return status too?
        # For now, assume success if no exception.
        return {"status": "completed"}
    except Exception as e:
         console.print(f"[red]Failed to generate report automatically: {e}[/red]")
         return {"status": "failed", "reason": str(e)} 