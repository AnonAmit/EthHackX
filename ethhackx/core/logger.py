# Placeholder for logging configuration
import logging
import os
from .config import LOGS_DIR

def setup_logging(log_level=logging.INFO, console_log_level=logging.WARNING):
    """Configures the logging for the application.

    Args:
        log_level: The minimum level to log to the file.
        console_log_level: The minimum level to log to the console.
    """
    log_file = LOGS_DIR / "ethhackx.log"

    # Ensure logs directory exists (redundant if config.ensure_directories works, but safe)
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
    except OSError as e:
        # Use console print here as logger might not be set up
        print(f"[bold red]Fatal Error: Could not create logs directory {LOGS_DIR}: {e}[/bold red]")
        # Optionally exit or raise?
        return # Prevent further logging setup if dir fails

    # Setup root logger
    # Log INFO and above to file
    # Log WARNING and above to console (using RichHandler)
    try:
        from rich.logging import RichHandler
        console_handler = RichHandler(rich_tracebacks=True, show_path=False, level=console_log_level)
    except ImportError:
        # Fallback if rich isn't installed (should be, but safe)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_log_level)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)

    # Define formatters
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_formatter = logging.Formatter('%(message)s') # RichHandler does its own formatting

    file_handler.setFormatter(file_formatter)
    if not isinstance(console_handler, RichHandler):
        console_handler.setFormatter(console_formatter)

    # Get the root logger and configure it
    root_logger = logging.getLogger()
    root_logger.setLevel(min(log_level, console_log_level)) # Set root logger to the lower level
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Example: Get a logger for a specific module
    # log = logging.getLogger('ethhackx.recon')
    # log.info('Reconnaissance module started')

    # Disable overly verbose library loggers if necessary
    # logging.getLogger("requests").setLevel(logging.WARNING)
    # logging.getLogger("urllib3").setLevel(logging.WARNING)


# Note: setup_logging() is called from ethhackx.py when interactive mode starts. 