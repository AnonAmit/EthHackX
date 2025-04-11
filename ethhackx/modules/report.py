# Placeholder for Reporting module
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
import questionary
import json
from datetime import datetime
import logging # Import logging

from ..core import storage, cli # Relative imports

log = logging.getLogger(__name__)
console = Console()

def generate_final_report(target):
    """Main function for the Reporting module."""
    log.info(f"Starting Report generation for target: {target}")
    console.print(f"\n[bold magenta]Generating Final Report for: {target}[/bold magenta]")

    # 1. Load all existing results for the target
    console.print("Loading saved results...")
    all_data = storage.load_all_results(target)

    if not all_data:
        log.warning(f"No results found for target '{target}' during report generation.")
        console.print(f"[yellow]No results found for target '{target}' in reports directory.[/yellow]")
        input("Press Enter to continue...")
        return

    log.info(f"Found {len(all_data)} module(s) with results for {target}.")

    # 2. Ask user for desired report format
    while True:
        report_format = cli.report_menu()
        if report_format == "back":
            break

        log.info(f"Selected report format: {report_format}")
        try:
            if report_format == "markdown":
                generate_markdown_report(target, all_data)
                break # Assume report generated, return to main menu
            elif report_format == "json":
                generate_json_summary(target, all_data)
                break
            # elif report_format == "html": # Placeholder for future
            #     generate_html_report(target, all_data)
            #     break
            else:
                log.warning(f"Unknown report format selected: {report_format}")
                console.print("[yellow]Option not implemented yet.[/yellow]")
                input("Press Enter to continue...")
        except Exception as e:
            log.exception(f"Error generating report ({report_format}) for {target}")
            console.print(f"[bold red]An unexpected error occurred during report generation: {e}[/bold red]")
            input("[yellow]Press Enter to continue...[/yellow]")

    log.info(f"Exiting Report module for target: {target}")

# --- Markdown Report Generation --- #
def generate_markdown_report(target, all_data):
    """Generates a Markdown formatted report."""
    log.info(f"Generating Markdown report for {target}")
    console.print("\n[cyan]Generating Markdown Report...[/cyan]")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace('://', '_').replace('/', '_').replace(':', '_')[:50] # Use length limit
    report_filename = f"EthHackX_Report_{sanitized_target}_{timestamp}.md"
    report_filepath = storage.REPORTS_DIR / report_filename

    md_content = []
    try:
        # --- Build Markdown Content --- #
        md_content.append(f"# EthHackX Security Assessment Report")
        md_content.append(f"**Target:** `{target}`")
        md_content.append(f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md_content.append("--- ")

        # Define a logical order for modules in the report
        module_order = ['recon_passive', 'recon_active', 'scan_sslscan', 'scan_nikto', 'scan_nuclei', 'scan_wpscan', 'exploit_sqlmap', 'exploit_xss_basic', 'exploit_lfi_basic', 'postexploit_privesc', 'postexploit_filesearch', 'postexploit_passwords', 'postexploit_persistence']
        # Get all unique module prefixes from the data
        available_module_prefixes = set(key.split('_')[0] + ('_' + key.split('_')[1] if key.startswith('recon') or key.startswith('exploit') or key.startswith('postexploit') else '') for key in all_data.keys())

        processed_modules = set()

        # Process modules in predefined order
        for module_key in module_order:
            if module_key in all_data:
                process_module_results(module_key, all_data[module_key], md_content)
                processed_modules.add(module_key)

        # Process any remaining modules not in the predefined order
        for module_key, results_list in all_data.items():
            if module_key not in processed_modules:
                log.debug(f"Processing module '{module_key}' not in predefined order.")
                process_module_results(module_key, results_list, md_content)

        # --- End of Content Building --- #

    except Exception as build_err:
        log.exception("Failed to build Markdown report content.")
        console.print(f"[red]Error building report content: {build_err}[/red]")
        # Add error to report if possible
        if md_content:
            md_content.append("\n--- ")
            md_content.append("## REPORT GENERATION ERROR")
            md_content.append(f"An error occurred during report generation: {build_err}")

    # --- Write the report file --- #
    try:
        with open(report_filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(md_content))
        log.info(f"Markdown report saved successfully to: {report_filepath}")
        console.print(f"[bold green]Markdown report saved to: {report_filepath}[/bold green]")

        # Optionally offer to display it (only in interactive mode - check?)
        # For simplicity, always ask for now.
        display = questionary.confirm("Display report preview in console? (May be long)", default=False).ask()
        if display:
            log.debug("Displaying Markdown preview in console.")
            # Add check for very large reports?
            report_str = "\n".join(md_content)
            if len(report_str) > 20000: # Arbitrary limit to prevent console flooding
                 log.warning("Report preview too long, skipping console display.")
                 console.print("[yellow]Report preview is very long, skipping console display to avoid issues.[/yellow]")
            else:
                try:
                    console.print(Panel(Markdown(report_str), title="Report Preview", border_style="blue"))
                except Exception as display_err:
                    log.error(f"Failed to display Markdown preview: {display_err}")
                    console.print("[red]Could not display preview (report might be too complex for console rendering).[/red]")

    except IOError as e:
        log.exception(f"Error writing Markdown report file: {report_filepath}")
        console.print(f"[red]Error writing report file: {e}[/red]")
    except Exception as e:
        log.exception(f"An unexpected error occurred during report file write/display: {report_filepath}")
        console.print(f"[red]An unexpected error occurred during report finalization: {e}[/red]")

    input("Press Enter to continue...")

def process_module_results(module_key, results_list, md_content):
    """Helper function to format results for a specific module key into Markdown."""
    clean_module_name = module_key.replace('_', ' ').title()
    md_content.append(f"\n## {clean_module_name} Findings")
    log.debug(f"Adding section for {clean_module_name} with {len(results_list)} result file(s).")

    if not results_list:
        md_content.append("*No results found for this section.*")
        return

    # Sort results by filename (which includes timestamp)
    results_list.sort(key=lambda x: x.get('file', ''))

    for result_item in results_list:
        data = result_item.get('data')
        source_file = result_item.get('file', 'Unknown source')
        md_content.append(f"\n### Source: `{source_file}`")

        if data is None:
            log.warning(f"Result data for {source_file} is None, skipping detailed formatting.")
            md_content.append("*(Error: Result data missing or empty)*")
            continue

        # --- Customize formatting based on expected data structure --- #
        try:
            # Passive Recon
            if module_key == 'recon_passive':
                if 'subdomains' in data:
                    md_content.append("#### Subdomains Found:")
                    md_content.append("```")
                    md_content.extend(data.get('subdomains', []) or ["*None found*"])
                    md_content.append("```")
                if 'whois' in data:
                     md_content.append("#### WHOIS Information:")
                     if isinstance(data['whois'], dict) and 'raw_output' in data['whois']:
                          md_content.append("```")
                          md_content.append(data['whois']['raw_output'] or "*No raw output*")
                          md_content.append("```")
                     elif isinstance(data['whois'], dict):
                         md_content.append("```json")
                         md_content.append(json.dumps(data['whois'], indent=2, default=str))
                         md_content.append("```")
                if 'dns' in data and isinstance(data.get('dns'), dict):
                    md_content.append(f"#### DNS Records (Tool: {data['dns'].get('tool', 'unknown')}):")
                    md_content.append("```")
                    md_content.extend(data['dns'].get('records', []) or ["*None found*"])
                    md_content.append("```")

            # Active Recon (Nmap)
            elif module_key.startswith('recon_active'):
                scan_type = module_key.split('_')[-1].replace('nmap', '') # Get type like 'quick', 'standard'
                md_content.append(f"#### Nmap Scan ({scan_type.title()}) Output:")
                if data.get('status') == 'completed' and data.get('output'):
                    md_content.append("```")
                    md_content.append(data['output'])
                    md_content.append("```")
                elif data.get('status') == 'failed':
                     md_content.append(f"*Scan Failed: {data.get('reason', 'Unknown')}*" )
                     md_content.append(f"*Command: `{data.get('command', 'N/A')}`*" )
                elif data.get('raw_output'): # Fallback
                     md_content.append("```")
                     md_content.append(data['raw_output'])
                     md_content.append("```")
                else:
                    md_content.append(f"*No standard output captured. Status: {data.get('status', 'unknown')}*" )

            # Scans (Nikto, Nuclei, SSLScan, WPScan)
            elif module_key.startswith('scan_'):
                if module_key == 'scan_nikto':
                     md_content.append(f"#### Nikto Scan Results:")
                     summary = data.get('summary', {})
                     if summary.get('vulnerabilities'):
                          md_content.append(f"*Potential Items Found: {summary.get('vulnerabilities_count', 0)}*" )
                          md_content.append("```")
                          for vuln in summary['vulnerabilities']:
                              md_content.append(f"+ {vuln}")
                          md_content.append("```")
                          md_content.append("\n*(See raw output below for details)*")
                     md_content.append("\n**Raw Output:**")
                     md_content.append("```")
                     md_content.append(data.get('raw_output', '*No raw output*'))
                     md_content.append("```")
                elif module_key == 'scan_nuclei':
                    md_content.append(f"#### Nuclei Scan Findings:")
                    findings = data.get('findings', [])
                    if findings:
                        count = 0
                        for finding in findings:
                             info = finding.get('info', {})
                             if finding.get('matcher-status', False):
                                 count+=1
                                 severity = info.get('severity', 'unknown').upper()
                                 name = info.get('name', 'Unknown Finding')
                                 matched = finding.get('matched-at', '')
                                 severity_prefix = {
                                     "CRITICAL": "🚨 CRITICAL:", "HIGH": "🔥 HIGH:", "MEDIUM": "⚠️ MEDIUM:",
                                     "LOW": "ℹ️ LOW:", "INFO": "📄 INFO:"
                                 }.get(severity, f"[{severity}]:")
                                 md_content.append(f"- **{severity_prefix}** {name} (`{matched}`)")
                        if count == 0:
                            md_content.append("*No matched findings reported by Nuclei.*")
                        md_content.append("\n*(Full details in JSON source file)*")
                    else:
                         md_content.append("*No findings array present. Check raw output.*")
                         if data.get('raw_output'):
                            md_content.append("\n**Raw Output (May be JSON lines):**")
                            md_content.append("```")
                            md_content.append(data.get('raw_output'))
                            md_content.append("```")
                elif module_key == 'scan_sslscan':
                     md_content.append(f"#### SSLScan Results:")
                     summary = data.get('summary', {})
                     if summary.get('weak_points_detected'):
                          md_content.append(f"**Potential Weaknesses Found:**" )
                          for point in summary['weak_points_detected']:
                              md_content.append(f"- {point}")
                          md_content.append("\n*(See raw output below for details)*")
                     md_content.append("\n**Raw Output:**")
                     md_content.append("```")
                     md_content.append(data.get('raw_output', '*No raw output*'))
                     md_content.append("```")
                elif module_key == 'scan_wpscan':
                     md_content.append(f"#### WPScan Results:")
                     if data.get('wp_check_error'):
                         md_content.append(f"*Note: WP Check failed before scan: {data['wp_check_error']}*" )
                     md_content.append("```")
                     md_content.append(data.get('raw_output', '*No raw output*'))
                     md_content.append("```")

            # Exploits (SQLMap, Basic XSS/LFI)
            elif module_key.startswith('exploit_'):
                 if module_key == 'exploit_sqlmap':
                    md_content.append(f"#### SQLMap Scan ({data.get('scan_type', 'unknown')}):")
                    md_content.append(f"*Command: `{data.get('command')}`*" )
                    md_content.append("**Output:**")
                    md_content.append("```")
                    md_content.append(data.get('output', '*No output captured*'))
                    md_content.append("```")
                    if data.get('errors'):
                        md_content.append("**Errors/Warnings:**")
                        md_content.append("```")
                        md_content.append(data.get('errors'))
                        md_content.append("```")
                 elif module_key == 'exploit_xss_basic':
                     md_content.append(f"#### Basic XSS Parameter Check:")
                     if data.get('potentially_vulnerable_params'):
                         md_content.append("**Potential Reflection Found in Parameters:**")
                         md_content.append("```")
                         md_content.extend(data['potentially_vulnerable_params'])
                         md_content.append("```")
                         md_content.append("**Note:** Reflection does not guarantee execution. Manual verification needed.")
                     else:
                         md_content.append("*No basic reflection detected in tested parameters.*")
                 elif module_key == 'exploit_lfi_basic':
                     md_content.append(f"#### Basic LFI Parameter Check:")
                     if data.get('potential_findings'):
                         md_content.append("**Potential LFI Findings:**")
                         for finding in data['potential_findings']:
                             md_content.append(f"- Param: `{finding['param']}`, Payload: `{finding['payload']}`, Reason: {finding['reason']}")
                         md_content.append("**Note:** Manual verification needed.")
                     else:
                          md_content.append("*No basic LFI detected in tested parameters.*")

            # Post-Exploit Checklists
            elif module_key.startswith('postexploit_'):
                category = data.get('category', module_key.replace('postexploit_', ''))
                md_content.append(f"#### Post-Exploit Info: {category.replace('_', ' ').title()}")
                if data.get('viewed') == True:
                    md_content.append("*Checklist/Techniques viewed.*")
                else: # Should not happen with current logic, but good fallback
                     md_content.append("*Data recorded, details in source file.*")
                # Could add the actual checklist text here if needed by reading it from post_exploit?

            # Default fallback
            else:
                log.warning(f"No specific Markdown formatting found for module key: {module_key}. Dumping JSON.")
                md_content.append(f"#### Raw Data ({module_key}):")
                md_content.append("```json")
                md_content.append(json.dumps(data, indent=2, default=str))
                md_content.append("```")
        except Exception as format_err:
            log.exception(f"Error formatting data for {source_file} in Markdown report.")
            md_content.append("*(Error formatting details for this result)*")
            try:
                md_content.append("**Raw Data Fallback:**")
                md_content.append("```json")
                md_content.append(json.dumps(data, indent=2, default=str))
                md_content.append("```")
            except Exception:
                md_content.append("*(Failed to dump raw data)*")

# --- JSON Summary Generation --- #
def generate_json_summary(target, all_data):
    """Generates a combined JSON summary of all results."""
    log.info(f"Generating JSON summary report for {target}")
    console.print("\n[cyan]Generating JSON Summary Report...[/cyan]")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace('://', '_').replace('/', '_').replace(':', '_')[:50] # Apply length limit
    report_filename = f"EthHackX_Summary_{sanitized_target}_{timestamp}.json"
    report_filepath = storage.REPORTS_DIR / report_filename

    # Structure the summary
    summary_data = {
        "report_target": target,
        "report_generated": datetime.now().isoformat(),
        "results_by_module": all_data # Contains list of findings per module file
    }
    log.debug(f"Prepared JSON summary data for {target}. Module count: {len(all_data)}")

    try:
        with open(report_filepath, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=4, default=str) # Added default=str for safety
        log.info(f"JSON summary report saved successfully to: {report_filepath}")
        console.print(f"[bold green]JSON summary report saved to: {report_filepath}[/bold green]")
    except IOError as e:
        log.exception(f"IOError writing JSON report file: {report_filepath}")
        console.print(f"[red]Error writing JSON report file: {e}[/red]")
    except TypeError as e:
         log.exception(f"TypeError writing JSON report file: {report_filepath} (data might not be serializable)")
         console.print(f"[red]Error serializing data for JSON report: {e}[/red]")
    except Exception as e:
        log.exception(f"An unexpected error occurred during JSON report generation: {report_filepath}")
        console.print(f"[red]An unexpected error occurred during JSON report generation: {e}[/red]")

    input("Press Enter to continue...")

# TODO: Optional HTML Generation (e.g., using Markdown library + CSS or Pandoc)
# def generate_html_report(target, all_data):
#    console.print("[yellow]HTML report generation not implemented yet.[/yellow]")
#    input("Press Enter to continue...") 