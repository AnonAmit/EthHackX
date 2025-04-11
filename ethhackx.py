#!/usr/bin/env python3

import argparse
from rich.console import Console
import sys
import logging # Import logging
import questionary # <-- Add this import

# Import core components (adjust paths if necessary)
from ethhackx.core import cli, config, executor, logger, storage # Added imports
# Import module placeholders (will be used later)
from ethhackx.modules import recon, scan, exploit, post_exploit, auto, report, utils_mod # Uncommented and added imports

log = logging.getLogger(__name__) # Setup logger for this file
console = Console()

# Map action keys to module functions
MODULE_MAP = {
    "recon": recon.run_reconnaissance,
    "scan": scan.run_scan, # Placeholder function needed in scan.py
    "exploit": exploit.run_exploitation,
    "post_exploit": post_exploit.run_post_exploitation,
    "auto": auto.run_auto_attack,
    "utils": utils_mod.run_utilities, # Placeholder function needed in utils_mod.py
    "report": report.generate_final_report, # Placeholder function needed in report.py
}

def run_module(module_name, target):
    """Runs the selected module's main function."""
    log.info(f"Attempting to run module '{module_name}' for target: {target}")
    if module_name in MODULE_MAP:
        module_func = MODULE_MAP[module_name]
        try:
            # Call the appropriate module function
            log.debug(f"Executing module function: {module_func.__name__}")
            module_func(target)
            log.info(f"Module '{module_name}' finished successfully.")
        except NotImplementedError:
            log.warning(f"Module '{module_name}' function ({module_func.__name__}) is not implemented.")
            console.print(f"[yellow]'{module_name.capitalize()}' module function not implemented yet.[/yellow]")
            input("Press Enter to continue...") # Pause for user
        except Exception as e:
            log.exception(f"Error running module '{module_name}' ({module_func.__name__}) for target {target}")
            console.print(f"[bold red]Error running {module_name} module: {e}[/bold red]")
            input("Press Enter to continue...") # Pause for user
    else:
        log.error(f"Unknown module requested: {module_name}")
        console.print(f"[red]Unknown module: {module_name}[/red]")
        input("Press Enter to continue...")
    log.debug(f"Exiting run_module for '{module_name}'")

def main():
    log.info("EthHackX application starting.")
    parser = argparse.ArgumentParser(description="EthHackX - Interactive Ethical Hacking Framework")
    # Add arguments later, e.g., for headless mode
    parser.add_argument('-t', '--target', help='Target domain/IP (required for headless mode)')
    parser.add_argument('--headless', action='store_true', help='Run Auto Attack sequence non-interactively')
    args = parser.parse_args()

    # --- Headless Mode Check --- #
    if args.headless:
        log.info(f"Headless mode activated for target: {args.target}")
        if not args.target:
            log.error("Headless mode attempted without a target.")
            console.print("[bold red]Error: --target is required when using --headless mode.[/bold red]")
            sys.exit(1)
        console.print(f"[yellow]Running in Headless Mode for target: {args.target}[/yellow]")
        # Directly run auto-attack sequence
        try:
            # Pass headless=True to the auto attack function
            log.info("Starting headless auto attack sequence.")
            auto.run_auto_attack(args.target, headless=True)
            log.info("Headless auto attack sequence finished successfully.")
        except Exception as e:
            log.exception("Headless Auto Attack sequence failed.")
            console.print(f"[bold red]Headless Auto Attack failed: {e}[/bold red]")
            sys.exit(1)
        console.print("[green]Headless Auto Attack finished.[/green]")
        sys.exit(0) # Exit cleanly after headless run

    # --- Interactive Mode (Default) --- #
    cli.display_banner()

    # Basic setup
    logger.setup_logging() # Activate logging
    log.info("EthHackX interactive session setup complete.")
    # console.print(f"Logs will be saved to: {config.LOGS_DIR / 'ethhackx.log'}") # Optional: Inform user

    current_target = config.get_last_target()
    log.debug(f"Initial target loaded: {current_target}")

    try: # Add a top-level try block for the interactive loop
        while True:
            if not current_target:
                log.info("No current target set, prompting user.")
                current_target = cli.get_target()
                if current_target: # Check if target was actually set
                    log.info(f"New target set by user: {current_target}")
                    config.set_last_target(current_target)
                else:
                    log.warning("User cancelled target selection or entered empty target.")
                    # cli.exit_app() handles exit message, just break loop
                    break
            else:
                # Reconfirm or change target
                 log.debug(f"Confirming or changing current target: {current_target}")
                 console.print(f"\nCurrent Target: [bold magenta]{current_target}[/bold magenta]") # Added newline
                 change_target = questionary.confirm("Change target?", default=False).ask()
                 if change_target is None: # Handle Ctrl+C
                     log.info("Ctrl+C detected during target confirmation. Exiting.")
                     cli.exit_app()
                 elif change_target:
                     log.info("User chose to change target.")
                     current_target = cli.get_target(last_target=current_target)
                     if current_target:
                         log.info(f"New target set: {current_target}")
                         config.set_last_target(current_target)
                     else:
                         log.warning("User cancelled target change or entered empty target.")
                         # Keep the old target in this case?
                         console.print("[yellow]Target not changed.[/yellow]")
                         current_target = config.get_last_target() # Re-fetch the last saved target

            # Ensure target is valid before proceeding
            if not current_target:
                log.error("No valid target available after prompt/change. Exiting.")
                console.print("[bold red]Target cannot be empty. Exiting.[/bold red]")
                cli.exit_app()
                break # Exit loop

            log.debug("Displaying main menu.")
            action = cli.main_menu()
            log.info(f"Main menu action selected: {action}")

            if action == "exit":
                log.info("User selected 'exit' from main menu.")
                cli.exit_app()
                break
            elif action:
                run_module(action, current_target) # Pass target to the module runner
            else:
                # Handle case where user might cancel the prompt (Ctrl+C)
                log.info("Ctrl+C detected during main menu selection. Exiting.")
                cli.exit_app()
                break # Exit loop

    except KeyboardInterrupt:
        log.info("KeyboardInterrupt (Ctrl+C) caught in main loop. Exiting gracefully.")
        cli.exit_app()
    except Exception as e:
        log.exception("An unexpected error occurred in the main interactive loop.")
        console.print(f"\n[bold red]An critical unexpected error occurred: {e}[/bold red]")
        console.print("[yellow]Please check the log file for details. Exiting.[/yellow]")
        # Optionally try to save state here if needed
        sys.exit(1)

    log.info("EthHackX application finished.")

if __name__ == "__main__":
    main() 