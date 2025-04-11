# Placeholder for Vulnerability Scanning module
from rich.console import Console
import questionary
import re # For parsing Nikto output
import json # For parsing Nuclei JSON output
import logging # Import logging

from ..core import cli, executor, storage # Relative imports

# Get logger
log = logging.getLogger(__name__)
console = Console()

def run_scan(target):
    """Main function for the Vulnerability Scanning module."""
    log.info(f"Starting Scan module for target: {target}")
    console.print(f"\n[bold blue]Initiating Vulnerability Scanning Module for: {target}[/bold blue]")

    # Basic check if target looks like a URL for web scanners
    is_web_target = target.startswith('http://') or target.startswith('https://')
    if not is_web_target:
        log.warning(f"Target '{target}' is not a URL. Web scanners might fail.")
        console.print(f"[yellow]Warning: Target '{target}' does not look like a URL (http/https). Web scanners might fail.[/yellow]")
        confirm = questionary.confirm("Continue anyway?", default=False).ask()
        if confirm is None or not confirm:
            log.info("Scan cancelled by user due to non-URL target.")
            return

    while True:
        action = cli.scan_menu() # Use the menu from core.cli
        if action == "back":
            break

        log.info(f"Running scan action: {action} for target: {target}")
        try:
            if action == "nikto":
                run_nikto_scan(target)
            elif action == "nuclei":
                run_nuclei_scan(target)
            elif action == "sslscan":
                run_ssl_scan(target)
            elif action == "wpscan":
                run_wpscan(target)
            # No need for else, cli menu handles unknown options
        except Exception as e:
             log.exception(f"Error during scan action {action} for {target}")
             console.print(f"[bold red]An unexpected error occurred during {action} scan: {e}[/bold red]")
             input("[yellow]Press Enter to continue...[/yellow]")

    log.info(f"Exiting Scan module for target: {target}")

# --- Nikto Scan --- #
def run_nikto_scan(target):
    """Runs Nikto web server scanner against the target."""
    log.info(f"Running Nikto scan on {target}")
    console.print(f"\n[cyan]-- Running Nikto Scan on {target} --[/cyan]")
    tool = "nikto"
    if not executor.check_tool_installed(tool):
        log.error("Nikto tool not found.")
        console.print(f"[red]Error: {tool} not found. Please install Nikto.[/red]")
        console.print("[yellow](Often available via package managers: sudo apt install nikto / brew install nikto)[/yellow]")
        input("Press Enter to continue...")
        return

    console.print("[yellow]Nikto scans can take some time...[/yellow]")
    command = [tool, "-h", target, "-Format", "txt"] # Simple text output
    # Consider adding -Tuning options later if needed

    stdout, stderr = executor.run_command(command)

    results = {"raw_output": stdout or "", "errors": stderr or ""}
    if stdout:
        log.info(f"Nikto scan completed for {target}")
        console.print("[green]Nikto scan completed.[/green]")
        # Basic parsing for summary
        vulnerabilities_found = []
        try:
             vulnerabilities_found = re.findall(r'^\+ (.*)$', stdout, re.MULTILINE)
             log.debug(f"Parsed {len(vulnerabilities_found)} potential findings from Nikto output.")
        except Exception as parse_err:
             log.error(f"Failed to parse Nikto output: {parse_err}")

        summary = {
            "target": target,
            "vulnerabilities_count": len(vulnerabilities_found),
            "vulnerabilities": vulnerabilities_found
        }
        console.print(f"Found {summary['vulnerabilities_count']} potential items.")
        # Optionally print findings
        # for vuln in summary['vulnerabilities']:
        #     console.print(f"  - {vuln}")
        console.print("--- Nikto Output --- (Saving full output to results file)")
        preview_lines = stdout.splitlines()[:15]
        console.print("\n".join(preview_lines))
        if len(stdout.splitlines()) > 15: console.print("... (output truncated in console) ...")
        console.print("--- End Nikto Output ---")
        results["summary"] = summary # Add summary to saved results
    else:
        log.warning(f"Nikto scan did not return standard output for {target}. Stderr: {stderr}")
        console.print("[yellow]Nikto scan did not return standard output.[/yellow]")
        if stderr: console.print(f"[red]Stderr:\n{stderr.strip()}[/red]") # Show stripped stderr

    storage.save_results("scan_nikto", target, results)
    input("Press Enter to continue...")

# --- Nuclei Scan --- #
def run_nuclei_scan(target):
    """Runs Nuclei template-based scanner against the target."""
    log.info(f"Running Nuclei scan on {target}")
    console.print(f"\n[cyan]-- Running Nuclei Scan on {target} --[/cyan]")
    tool = "nuclei"
    if not executor.check_tool_installed(tool):
        log.error("Nuclei tool not found.")
        console.print(f"[red]Error: {tool} not found. Please install Nuclei.[/red]")
        console.print("[yellow](Download from: https://github.com/projectdiscovery/nuclei/releases)[/yellow]")
        console.print("[yellow]Ensure you have run 'nuclei -update-templates' recently.[/yellow]")
        input("Press Enter to continue...")
        return

    console.print("[yellow]Nuclei scan running... This might take a while.[/yellow]")
    command = [tool, "-u", target, "-silent", "-json"] # JSON output for easier parsing

    stdout, stderr = executor.run_command(command)

    results = {"findings": [], "errors": stderr or "", "raw_output": stdout or ""}
    if stdout:
        log.info(f"Nuclei scan completed for {target}. Parsing output.")
        console.print("[green]Nuclei scan completed.[/green]")
        findings_count = 0
        parsed_findings = []
        try:
            # Nuclei JSON output is line-delimited
            for line in stdout.strip().split('\n'):
                if line:
                    try:
                        finding = json.loads(line)
                        parsed_findings.append(finding)
                        # Print summary to console
                        info = finding.get('info', {})
                        severity = info.get('severity', 'unknown').upper()
                        name = info.get('name', 'Unknown Finding')
                        matcher_status = finding.get('matcher-status', False)
                        if matcher_status:
                            findings_count += 1
                            # Define color and style based on severity
                            style = ""
                            if severity == "CRITICAL":
                                style = "bold blink red on white"
                            elif severity == "HIGH":
                                style = "bold red"
                            elif severity == "MEDIUM":
                                style = "bold yellow"
                            elif severity == "LOW":
                                style = "bold cyan"
                            else: # INFO, UNKNOWN
                                style = "dim white"
                            console.print(f"  - [[{style}]{severity}[/{style}]] {name} ({finding.get('matched-at', target)})")
                    except json.JSONDecodeError as json_err:
                         log.warning(f"Skipping invalid JSON line in Nuclei output: {json_err}. Line: '{line[:100]}...'")
                         continue # Skip this line

            results["findings"] = parsed_findings # Save successfully parsed findings
            log.info(f"Parsed {len(parsed_findings)} lines, found {findings_count} matched findings.")
            console.print(f"Found {findings_count} potential issues.")
            console.print("(Saving full JSON details to results file)")

        except Exception as e:
            log.exception(f"Error processing Nuclei output for {target}")
            console.print(f"[red]Error processing Nuclei output: {e}[/red]")
            # Results dict already contains raw_output

    else:
        log.warning(f"Nuclei scan did not return standard output for {target}. Stderr: {stderr}")
        console.print("[yellow]Nuclei scan did not return standard output.[/yellow]")
        if stderr: console.print(f"[red]Stderr:\n{stderr.strip()}[/red]")

    storage.save_results("scan_nuclei", target, results)
    input("Press Enter to continue...")

# --- SSL Scan --- #
def run_ssl_scan(target):
    """Runs sslscan to check SSL/TLS configuration."""
    log.info(f"Running SSLScan on target: {target}")
    console.print(f"\n[cyan]-- Running SSL/TLS Scan on {target} --[/cyan]")
    tool = "sslscan"
    if not executor.check_tool_installed(tool):
        log.error("SSLScan tool not found.")
        console.print(f"[red]Error: {tool} not found. Please install sslscan.[/red]")
        console.print("[yellow](Often available via package managers: sudo apt install sslscan / brew install sslscan)[/yellow]")
        input("Press Enter to continue...")
        return

    # Extract hostname/IP and optional port from target URL/string
    host = target
    port = None # Track port if specified
    try:
        if '://' in target:
            # Handle URLs (http://host:port/path or https://host/path etc.)
            host_part = target.split('://')[1].split('/')[0]
            if ':' in host_part:
                 host, port_str = host_part.split(':', 1)
                 try:
                     port = int(port_str)
                     log.debug(f"Parsed port {port} from URL")
                 except ValueError:
                      log.warning(f"Invalid port '{port_str}' in target URL '{target}', using host only.")
                      port = None # Reset port if invalid
            else:
                 host = host_part
        else:
            # Assume input is host or host:port if no protocol
             if ':' in target:
                 host, port_str = target.split(':', 1)
                 try:
                     port = int(port_str)
                     log.debug(f"Parsed port {port} from direct input")
                 except ValueError:
                      log.warning(f"Invalid port '{port_str}' in target '{target}', using host only.")
                      host = target # Reset host to the original input if port was invalid
                      port = None
             else:
                 host = target
        log.info(f"Extracted host: {host}, port: {port} for sslscan from {target}")
        console.print(f"[grey50]Scanning host: {host}{f':{port}' if port else ''} (using sslscan)[/grey50]")

    except Exception as e:
        log.exception(f"Failed to parse host/port from target '{target}'")
        console.print(f"[red]Error parsing target '{target}'. Please check format.[/red]")
        input("Press Enter to continue...")
        return

    console.print("[yellow]SSLScan running...[/yellow]")
    # Command: sslscan host or sslscan host:port
    scan_target = f"{host}:{port}" if port else host
    # Use --show-sigs for algorithm details if needed, basic scan for now
    command = [tool, "--no-colour", scan_target]

    stdout, stderr = executor.run_command(command, capture_output=True) # Capture for saving

    results = {"raw_output": stdout or "", "errors": stderr or ""}
    summary = {"target": scan_target, "weak_points_detected": []}

    if stdout:
        log.info(f"SSLScan completed for {scan_target}")
        console.print("[green]SSLScan completed.[/green]")
        # Simple check for vulnerabilities (e.g., SSLv3, weak ciphers)
        weak_points = []
        try:
            # Case-insensitive checks
            stdout_lower = stdout.lower()
            if "sslv2" in stdout_lower and "enabled" in stdout_lower:
                weak_points.append("SSLv2 enabled")
            if "sslv3" in stdout_lower and "enabled" in stdout_lower:
                weak_points.append("SSLv3 enabled")
            # Check for common weak ciphers (can be expanded)
            weak_cipher_markers = [" rc4", " des", " 3des", " export", " anon"]
            for marker in weak_cipher_markers:
                 # Check if the cipher is listed under 'Accepted' or similar positive context
                 if marker in stdout_lower and ("accepted" in stdout_lower or "preferred" in stdout_lower):
                     point = f"{marker.strip().upper()} cipher suite accepted"
                     if point not in weak_points:
                        weak_points.append(point)
                        log.debug(f"Detected weak point: {point}")
            # Check for heartbleed
            if "heartbleed" in stdout_lower and "vulnerable" in stdout_lower:
                 weak_points.append("Heartbleed vulnerability reported")
                 log.debug("Detected weak point: Heartbleed")
            # Add checks for poodle, beast, etc. if needed by parsing specific sslscan output sections

            summary["weak_points_detected"] = weak_points
            log.debug(f"SSLScan summary for {scan_target}: {summary}")

            if weak_points:
                console.print(f"[yellow]Detected potential weaknesses: {weak_points}[/yellow]")
            else:
                console.print("[green]Basic SSL/TLS checks passed (no obvious weak points found).[/green]")
        except Exception as parse_err:
            log.error(f"Failed to parse SSLScan output: {parse_err}")

        console.print("--- SSLScan Output --- (Saving full output to results file)")
        preview_lines = stdout.splitlines()[:20]
        console.print("\n".join(preview_lines))
        if len(stdout.splitlines()) > 20: console.print("... (output truncated in console) ...")
        console.print("--- End SSLScan Output ---")
        results["summary"] = summary

    else:
        log.warning(f"SSLScan did not return standard output for {scan_target}. Stderr: {stderr}")
        console.print("[yellow]SSLScan did not return standard output.[/yellow]")
        if stderr:
             # Handle common sslscan errors
            stderr_lower = stderr.lower()
            if "unavailable" in stderr_lower or "resolve" in stderr_lower or "connect" in stderr_lower:
                 log.error(f"SSLScan connection/resolution error for {scan_target}: {stderr.strip()}")
                 console.print(f"[red]Error: Could not connect to or resolve host: {scan_target}[/red]")
            else:
                 log.warning(f"SSLScan stderr: {stderr.strip()}") # Log other stderr as warning
                 console.print(f"[red]Stderr:\n{stderr.strip()}[/red]")

    storage.save_results("scan_sslscan", scan_target, results) # Save based on host:port
    input("Press Enter to continue...")

# --- WPScan --- #
def run_wpscan(target, headless=False): # Add headless flag if called from auto
    """Runs WPScan against the target WordPress site."""
    log.info(f"Running WPScan on {target}")
    console.print(f"\n[cyan]-- Running WPScan on {target} --[/cyan]")
    tool = "wpscan"
    if not executor.check_tool_installed(tool):
        log.error("WPScan tool not found.")
        console.print(f"[red]Error: {tool} not found.[/red]")
        console.print("[yellow]WPScan requires Ruby and manual installation (gem install wpscan).[/yellow]")
        console.print("[yellow]See: https://github.com/wpscanteam/wpscan[/yellow]")
        input("Press Enter to continue...")
        return

    # Check if target seems like a WordPress site (basic check)
    log.debug(f"Performing basic WP check for {target}")
    console.print("[yellow]Checking if target might be a WordPress site... (basic check)[/yellow]")
    is_likely_wp = False
    wp_check_error = None
    try:
        import requests
        common_paths = ["/wp-login.php", "/wp-admin/", "/wp-includes/js/wp-embed.min.js"]
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Mozilla/5.0 EthHackX'})
            session.timeout = 10 # Increased timeout slightly
            session.verify = False # Ignore SSL errors
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            for path in common_paths:
                check_url = target.rstrip('/') + path
                try:
                    log.debug(f"Checking WP path: {check_url}")
                    # Use HEAD request first for efficiency
                    response = session.head(check_url, allow_redirects=True)
                    if response.status_code < 400 or 'wp-' in response.headers.get('Link', ''):
                        is_likely_wp = True
                        log.info(f"Target {target} seems likely WP (found {path}, status {response.status_code}) via HEAD.")
                        console.print(f"[green]Target seems to be a WordPress site (check {path} ok).[/green]")
                        break
                    # If HEAD doesn't confirm, maybe try GET briefly?
                    # response = session.get(check_url, stream=True, allow_redirects=True)
                    # if response.status_code < 400 and 'wordpress' in response.text.lower()[:500]: ...
                    # response.close()
                except requests.exceptions.Timeout:
                    log.debug(f"Timeout checking WP path: {check_url}")
                    # Continue checking other paths
                except requests.exceptions.RequestException as req_err:
                    log.debug(f"Request exception checking WP path {check_url}: {req_err}")
                    pass # Ignore connection errors for this simple check

        if not is_likely_wp:
             log.info(f"Basic WP check failed for {target}")
             console.print("[yellow]Target does not immediately appear to be a WordPress site (basic check failed).[/yellow]")
             if not headless:
                 confirm = questionary.confirm("Run WPScan anyway?", default=False).ask()
                 if confirm is None or not confirm:
                     log.info("WPScan cancelled by user after failed WP check.")
                     return

    except ImportError:
        wp_check_error = "'requests' library not installed"
        log.error(f"Cannot perform WordPress check: {wp_check_error}")
        console.print(f"[red]Cannot perform WordPress check: {wp_check_error}.[/red]")
        if not headless:
            confirm = questionary.confirm("Run WPScan without checking if it's a WordPress site?", default=True).ask()
            if confirm is None or not confirm:
                 log.info("WPScan cancelled by user due to missing requests library.")
                 return
    except Exception as e:
        wp_check_error = str(e)
        log.exception("Error during WP check")
        console.print(f"[red]Error during WP check: {e}[/red]")
        if not headless:
            confirm = questionary.confirm("Run WPScan despite error during check?", default=False).ask()
            if confirm is None or not confirm:
                log.info("WPScan cancelled by user after WP check error.")
                return

    # Get WPScan options (only in interactive mode)
    enumerate_args = []
    if not headless:
        console.print("[yellow]WPScan running... This can take a significant amount of time.[/yellow]")
        console.print("[yellow]For full vulnerability data, an API token from wpscan.com might be required.[/yellow]")
        console.print("[yellow]Add it via 'wpscan --api-token YOUR_TOKEN' or config file.[/yellow]")

        wpscan_options_selected = questionary.checkbox(
            "Select WPScan enumeration options (optional):",
            choices=[
                questionary.Choice("Vulnerable Plugins (vp - recommended)", value="vp", checked=True),
                questionary.Choice("All Plugins (ap - slow)", value="ap"),
                questionary.Choice("Vulnerable Themes (vt - recommended)", value="vt", checked=True),
                questionary.Choice("All Themes (at - slow)", value="at"),
                questionary.Choice("User IDs (u)", value="u"),
                # questionary.Choice("Timthumbs (tt)", value="tt")
            ]
        ).ask()

        if wpscan_options_selected is None: # User cancelled
            log.info("WPScan cancelled by user at options selection.")
            console.print("[yellow]WPScan cancelled.[/yellow]")
            return

        if wpscan_options_selected:
            # Combine flags correctly: -e vp,vt,u
            enumerate_flags = ",".join(wpscan_options_selected)
            if enumerate_flags:
                 enumerate_args = ["-e", enumerate_flags]
    else: # Headless defaults
        log.info("Using default WPScan enumerations for headless mode: vp,vt")
        enumerate_args = ["-e", "vp,vt"] # Default recommended flags for headless

    # Construct command
    # Add --force to ignore WP version checks if needed
    # Add --random-user-agent
    # Consider --plugins-detection aggressive (slower)
    # Add --api-token from config if available
    command = [tool, "--url", target, "--no-banner", "--random-user-agent", "--disable-tls-checks"] + enumerate_args
    # TODO: Add --api-token argument if configured later

    stdout, stderr = executor.run_command(command)

    results = {"raw_output": stdout or "", "errors": stderr or "", "wp_check_error": wp_check_error}
    if stdout:
        log.info(f"WPScan completed for {target}")
        console.print("[green]WPScan completed.[/green]")
        # TODO: Add more sophisticated parsing for JSON output if desired (-f json)
        console.print("--- WPScan Output --- (Saving full output to results file)")
        preview_lines = stdout.splitlines()[:25]
        console.print("\n".join(preview_lines))
        if len(stdout.splitlines()) > 25: console.print("... (output truncated in console) ...")
        console.print("--- End WPScan Output ---")
        # You could parse for key findings like '[!]' lines
    else:
        log.warning(f"WPScan did not return standard output for {target}. Stderr: {stderr}")
        console.print("[yellow]WPScan did not return standard output.[/yellow]")
        if stderr: console.print(f"[red]Stderr:\n{stderr.strip()}[/red]")

    storage.save_results("scan_wpscan", target, results)
    input("Press Enter to continue...") 