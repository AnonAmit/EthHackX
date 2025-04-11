# Placeholder for results storage logic
import json
import os
from datetime import datetime
from .config import REPORTS_DIR
from rich.console import Console # Keep console for user feedback
import logging

log = logging.getLogger(__name__)
console = Console()

def save_results(module_name: str, target: str, data: dict):
    """Saves the results of a module execution to a JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize target for use in filename
    sanitized_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
    # Limit length of sanitized target in filename to avoid issues
    max_target_len = 50
    sanitized_target = sanitized_target[:max_target_len]

    filename = f"{module_name}_{sanitized_target}_{timestamp}.json"
    filepath = REPORTS_DIR / filename

    try:
        # Ensure reports directory exists (redundant but safe)
        os.makedirs(REPORTS_DIR, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        log.info(f"Results saved successfully to: {filepath}")
        console.print(f"[dim green]Results saved to: {filepath}[/dim green]") # User feedback

    except IOError as e:
        log.error(f"IOError saving results to {filepath}: {e}")
        console.print(f"[red]Error saving results file: {e}[/red]") # User feedback
    except TypeError as e:
         log.error(f"TypeError saving results to {filepath} (data might not be JSON serializable): {e}")
         console.print(f"[red]Error serializing results data: {e}[/red]") # User feedback
    except Exception as e:
        log.exception(f"An unexpected error occurred while saving results to {filepath}")
        console.print(f"[red]An unexpected error occurred while saving results: {e}[/red]")

def load_all_results(target: str):
    """Loads all result files for a specific target."""
    all_results = {}
    sanitized_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
    sanitized_target = sanitized_target[:50] # Use same truncation as saving
    log.info(f"Loading all results for target containing: _{sanitized_target}_")

    try:
        if not REPORTS_DIR.exists():
             log.warning(f"Reports directory not found: {REPORTS_DIR}")
             console.print(f"[yellow]Reports directory not found: {REPORTS_DIR}[/yellow]")
             return {}

        loaded_count = 0
        skipped_count = 0
        for filename in os.listdir(REPORTS_DIR):
            # Ensure the filename structure matches what save_results creates
            if filename.endswith(".json") and f"_{sanitized_target}_" in filename:
                filepath = REPORTS_DIR / filename
                # Extract module name robustly (handle potential extra underscores)
                parts = filename.split('_')
                if len(parts) < 3: # Expect at least module_target_timestamp.json
                     log.warning(f"Skipping file with unexpected name format: {filename}")
                     skipped_count += 1
                     continue
                module_name = parts[0]
                for i in range(1, len(parts) - 2): # Rebuild module name if it contained underscores
                     if parts[i] not in sanitized_target:
                          module_name += f"_{parts[i]}"
                     else:
                         break # Stop when target part is reached

                log.debug(f"Attempting to load result file: {filepath} for module: {module_name}")
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        if module_name not in all_results:
                            all_results[module_name] = []
                        all_results[module_name].append({"file": filename, "data": data})
                        loaded_count += 1
                except json.JSONDecodeError:
                    log.warning(f"Skipping corrupted JSON file: {filename}")
                    console.print(f"[yellow]Warning: Skipping corrupted file: {filename}[/yellow]")
                    skipped_count += 1
                except IOError as e:
                    log.error(f"Error reading result file {filename}: {e}")
                    console.print(f"[red]Error reading result file {filename}: {e}[/red]")
                    skipped_count += 1

        log.info(f"Finished loading results for target '{target}'. Loaded: {loaded_count}, Skipped/Errors: {skipped_count}")

    except Exception as e:
        log.exception(f"An unexpected error occurred while loading results for target {target}")
        console.print(f"[red]An unexpected error occurred while loading results: {e}[/red]")

    # Sort results within each module perhaps by timestamp if needed?
    # for module in all_results:
    #     all_results[module].sort(key=lambda x: x['file']) # Simple sort by filename

    return all_results 