# Placeholder for external command execution logic
import subprocess
import os
from rich.console import Console
import logging # Import logging

# Get a logger for this module
log = logging.getLogger(__name__) # Use __name__ for hierarchical logging

console = Console()

def run_command(command: list, capture_output=True, text=True, shell=False):
    """Runs an external command and returns its output."""
    cmd_str = ' '.join(command)
    log.info(f"Executing command: {cmd_str}")
    console.print(f"[grey50]Executing: {cmd_str}[/grey50]")
    try:
        # Ensure command list elements are strings
        cmd_str_list = [str(item) for item in command]
        process = subprocess.run(
            cmd_str_list,
            capture_output=capture_output,
            text=text,
            shell=shell,
            timeout=300
        )
        if process.returncode != 0:
            log.error(f"Command exited with non-zero status ({process.returncode}): {cmd_str}")
            log.debug(f"Stderr: {process.stderr}")
            console.print(f"[bold red]Error executing command (Code: {process.returncode}): {cmd_str}[/bold red]")
            if process.stderr:
                console.print(f"[red]Stderr:\n{process.stderr.strip()}[/red]")
        else:
            log.debug(f"Command finished successfully: {cmd_str}")
        return process.stdout, process.stderr
    except FileNotFoundError:
        error_msg = f"Command not found: {command[0]}. Please ensure it is installed and in PATH."
        log.error(error_msg)
        console.print(f"[bold red]Error: {error_msg}[/bold red]")
        return None, f"Command not found: {command[0]}"
    except subprocess.CalledProcessError as e:
        error_msg = f"Command exited with non-zero status ({e.returncode}): {cmd_str}"
        log.error(error_msg, exc_info=False) # Log basic error, not full stack trace usually
        log.debug(f"Stderr: {e.stderr}") # Log stderr for debugging
        console.print(f"[bold red]Error executing command (Code: {e.returncode}): {cmd_str}[/bold red]")
        if e.stderr:
            console.print(f"[red]Stderr:\n{e.stderr.strip()}[/red]")
        # Return output even on error for potential parsing by caller
        return e.stdout, e.stderr
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out: {cmd_str}"
        log.error(error_msg)
        console.print(f"[bold red]Error: {error_msg}[/bold red]")
        return None, "Command timed out"
    except Exception as e:
        # Catch unexpected errors
        log.exception(f"An unexpected error occurred running command: {cmd_str}") # Log full stack trace
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None, str(e)

def check_tool_installed(tool_name):
    """Checks if a tool is available in the system PATH."""
    log.debug(f"Checking if tool '{tool_name}' is installed.")
    try:
        # Use 'where' on Windows, 'command -v' on Unix-like
        cmd = ["where", tool_name] if os.name == 'nt' else ["command", "-v", tool_name]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.debug(f"Tool '{tool_name}' found.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        log.warning(f"Tool '{tool_name}' not found in PATH.")
        return False
    except Exception as e:
        log.exception(f"Unexpected error checking for tool '{tool_name}'")
        return False 