import os
import json
from pathlib import Path
import logging

log = logging.getLogger(__name__)

# Define base directory for the application data
# Use user's home directory for cross-platform compatibility
APP_NAME = "EthHackX"
CONFIG_DIR = Path.home() / f".{APP_NAME.lower()}"
STATE_FILE = CONFIG_DIR / "state.json"

# Define directories relative to the script execution (or workspace root)
# These are for outputs, not internal config
# Assuming config.py is in ethhackx/core/
try:
    WORKSPACE_DIR = Path(__file__).resolve().parents[2]
except IndexError:
    log.warning("Could not determine workspace directory relative to config.py. Using current working directory.")
    WORKSPACE_DIR = Path.cwd()

LOGS_DIR = WORKSPACE_DIR / "logs"
REPORTS_DIR = WORKSPACE_DIR / "reports"

def ensure_directories():
    """Creates necessary directories if they don't exist."""
    dirs_to_create = [CONFIG_DIR, LOGS_DIR, REPORTS_DIR]
    for dir_path in dirs_to_create:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
            log.debug(f"Ensured directory exists: {dir_path}")
        except OSError as e:
            log.error(f"Failed to create directory {dir_path}: {e}")
            # Depending on the directory, this might be critical
            if dir_path == CONFIG_DIR:
                log.critical(f"Cannot create config directory {CONFIG_DIR}. State saving/loading will fail.")
            # We don't raise here to allow the app to potentially continue
            # But logging should capture the failure.

def load_state():
    """Loads the application state from the JSON file."""
    ensure_directories()
    if not CONFIG_DIR.exists():
        log.error(f"Config directory {CONFIG_DIR} does not exist. Cannot load state.")
        return {"last_target": None}

    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
                log.info(f"Loaded state from {STATE_FILE}")
                return state
        except json.JSONDecodeError:
            log.error(f"Failed to decode JSON from state file: {STATE_FILE}. Returning default state.")
            return {"last_target": None}
        except IOError as e:
             log.error(f"Failed to read state file {STATE_FILE}: {e}")
             return {"last_target": None}
    else:
        log.info(f"State file {STATE_FILE} not found. Returning default state.")
        return {"last_target": None}

def save_state(state):
    """Saves the application state to the JSON file."""
    ensure_directories()
    if not CONFIG_DIR.exists():
         log.error(f"Config directory {CONFIG_DIR} does not exist. Cannot save state.")
         return

    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=4)
            log.info(f"Saved state to {STATE_FILE}")
    except IOError as e:
        # Handle potential write errors (e.g., permissions)
        log.error(f"Error saving state to {STATE_FILE}: {e}")
    except TypeError as e:
         log.error(f"Error serializing state data to JSON: {e}")

def get_last_target():
    """Retrieves the last used target from the state."""
    state = load_state()
    return state.get("last_target")

def set_last_target(target):
    """Updates the last used target in the state."""
    state = load_state()
    state["last_target"] = target
    save_state(state)

# Ensure directories are created when the module is imported
# This might run before logging is fully configured if imported early,
# but the ensure_directories function has its own error handling.
ensure_directories() 