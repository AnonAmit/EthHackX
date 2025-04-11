# Placeholder for Utilities module
from rich.console import Console
import questionary
import re
import base64
import urllib.parse
import hashlib
import logging # Import logging
import json # Added for geoip json decode errors

from ..core import cli # Relative imports

log = logging.getLogger(__name__) # Get logger
console = Console()

def run_utilities(target=None): # Target might not always be relevant here
    """Main function for the Utilities module."""
    log.info("Starting Utilities module.")
    console.print(f"\n[bold cyan]Initiating Utilities Module[/bold cyan]")

    while True:
        action = cli.utils_menu() # Use the menu from core.cli
        if action == "back":
            break

        log.info(f"Running utility action: {action}")
        try:
            if action == "hash_id":
                identify_hash()
            elif action == "encoder":
                run_encoder()
            elif action == "dorker":
                run_dork_generator()
            elif action == "geoip":
                run_geoip_lookup()
        except Exception as e:
             log.exception(f"Error during utility action {action}")
             console.print(f"[bold red]An unexpected error occurred in {action} utility: {e}[/bold red]")
             input("[yellow]Press Enter to continue...[/yellow]")

    log.info("Exiting Utilities module.")

# --- Hash Identifier --- #
# Based on patterns, not foolproof!
HASH_REGEX = {
    re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE): "MD5 / NTLM",
    re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE): "SHA-1",
    re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE): "SHA-224",
    re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE): "SHA-256",
    re.compile(r'^[a-f0-9]{96}$', re.IGNORECASE): "SHA-384",
    re.compile(r'^[a-f0-9]{128}$', re.IGNORECASE): "SHA-512",
    re.compile(r'^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$'): "MD5 Crypt", # $1$salt$hash
    re.compile(r'^\$2[axy]?\$[0-9]{2}\$[a-zA-Z0-9./]{53}$'): "Blowfish Crypt (bcrypt)", # $2a$cost$salt+hash
    re.compile(r'^\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}$'): "SHA-256 Crypt", # $5$rounds=N$salt$hash / $5$salt$hash
    re.compile(r'^\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}$'): "SHA-512 Crypt", # $6$rounds=N$salt$hash / $6$salt$hash
    re.compile(r'^[a-f0-9]{16}$', re.IGNORECASE): "MySQL323 / DES(Unix) / Half MD5?",
    re.compile(r'^\*[a-f0-9]{40}$', re.IGNORECASE): "MySQL5 (SHA1(SHA1(pass)))"
}

def identify_hash():
    """Identifies possible hash types based on regex patterns."""
    log.info("Starting Hash Identifier utility.")
    console.print("\n[cyan]--- Hash Identifier ---[/cyan]")
    hash_input = questionary.text("Enter the hash string:").ask()

    if hash_input is None or not hash_input.strip():
        log.warning("Hash identification cancelled or empty input.")
        console.print("[yellow]No hash entered.[/yellow]")
        input("Press Enter to continue...")
        return

    hash_input = hash_input.strip()
    log.debug(f"Attempting to identify hash: {hash_input}")
    possible_types = []
    try:
        for regex, hash_type in HASH_REGEX.items():
            if regex.match(hash_input):
                possible_types.append(hash_type)
    except Exception as e:
        log.exception("Error during hash regex matching.")
        console.print(f"[red]An error occurred during pattern matching: {e}[/red]")
        # Continue to show basic info if possible

    if possible_types:
        log.info(f"Identified possible hash types for '{hash_input}': {possible_types}")
        console.print(f"[green]Possible hash types for '{hash_input}':[/green]")
        for h_type in possible_types:
            console.print(f"  - {h_type}")
    else:
        log.info(f"Could not identify hash type for '{hash_input}' based on patterns.")
        console.print(f"[yellow]Could not identify hash type based on known patterns for '{hash_input}'.[/yellow]")
        # Check length
        try:
            length = len(hash_input)
            console.print(f"Length: {length}")
            # Basic character set check
            if all(c in '0123456789abcdefABCDEF' for c in hash_input):
                console.print("Character set: Hexadecimal")
            elif all(c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./$' for c in hash_input):
                console.print("Character set: Likely Crypt format (alphanumeric + ./$)")
            elif all(c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/' for c in hash_input.rstrip('=')):
                 if length % 4 == 0:
                     console.print("Character set: Looks like Base64 (check padding)")
        except Exception as e:
             log.error(f"Error performing basic analysis on hash string: {e}")

    console.print("[grey50]Note: Identification is based on common patterns and may not be definitive.[/grey50]")
    input("Press Enter to continue...")


# --- Payload Encoder --- #
def run_encoder():
    """Encodes or decodes a string using various formats."""
    log.info("Starting Payload Encoder/Decoder utility.")
    console.print("\n[cyan]--- Payload Encoder / Decoder ---[/cyan]")

    operation = questionary.select("Choose operation:", choices=["Encode", "Decode"]).ask()
    if operation is None:
        log.info("Encoder operation cancelled.")
        return

    encoding_format = questionary.select("Choose format:", choices=["Base64", "Hex", "URL Encoding"]).ask()
    if encoding_format is None:
         log.info("Encoder format selection cancelled.")
         return

    input_string = questionary.text(f"Enter the string to {operation.lower()}:").ask()
    if input_string is None or not input_string:
        log.warning("Encoder cancelled or empty input string.")
        console.print("[yellow]No input string provided.[/yellow]")
        input("Press Enter to continue...")
        return

    output_string = ""
    error_message = ""
    log.debug(f"Attempting to {operation} '{input_string[:50]}...' using {encoding_format}")

    try:
        if operation == "Encode":
            input_bytes = input_string.encode('utf-8')
            if encoding_format == "Base64":
                output_string = base64.b64encode(input_bytes).decode('utf-8')
            elif encoding_format == "Hex":
                output_string = input_bytes.hex()
            elif encoding_format == "URL Encoding":
                output_string = urllib.parse.quote(input_string)
        elif operation == "Decode":
            if encoding_format == "Base64":
                missing_padding = len(input_string) % 4
                padded_input = input_string
                if missing_padding:
                    padded_input += '=' * (4 - missing_padding)
                    log.debug("Added Base64 padding.")
                output_string = base64.b64decode(padded_input).decode('utf-8', errors='replace')
            elif encoding_format == "Hex":
                output_string = bytes.fromhex(input_string).decode('utf-8', errors='replace')
            elif encoding_format == "URL Encoding":
                output_string = urllib.parse.unquote(input_string)
        log.info(f"Successfully {operation.lower()}d string using {encoding_format}. Input length: {len(input_string)}, Output length: {len(output_string)}")
    except Exception as e:
        log.exception(f"Error during {operation.lower()}ing ({encoding_format}) utility.")
        error_message = f"Error during {operation.lower()}ing ({encoding_format}): {e}"

    if error_message:
        console.print(f"[bold red]{error_message}[/bold red]")
    elif output_string is not None:
        console.print(f"\n[green]Input:[/green] {input_string}")
        console.print(f"[green]{operation}d Output ({encoding_format}):[/green]")
        console.print(f"[bold cyan]{output_string}[/bold cyan]")
    else:
        log.warning(f"Operation resulted in None/empty output for {operation}/{encoding_format}")
        console.print("[yellow]Operation resulted in empty or invalid output.[/yellow]")

    input("Press Enter to continue...")


# --- Dork Generator --- #
def run_dork_generator():
    """Generates Google and GitHub dorks for a given domain or keyword."""
    log.info("Starting Dork Generator utility.")
    console.print("\n[cyan]--- Dork Generator ---[/cyan]")

    target_type = questionary.select("Generate dorks for:", choices=["Domain", "Keyword"]).ask()
    if target_type is None:
         log.info("Dork generator target type selection cancelled.")
         return

    if target_type == "Domain":
        domain = questionary.text("Enter the target domain (e.g., example.com):").ask()
        if domain is None or not domain.strip():
            log.warning("Dork generator cancelled or empty domain input.")
            console.print("[yellow]No domain entered.[/yellow]")
            input("Press Enter to continue...")
            return
        domain = domain.strip()
        log.info(f"Generating dorks for domain: {domain}")
        generate_domain_dorks(domain)
    elif target_type == "Keyword":
        keyword = questionary.text("Enter the keyword (e.g., 'admin login', 'database config'):").ask()
        if keyword is None or not keyword.strip():
             log.warning("Dork generator cancelled or empty keyword input.")
             console.print("[yellow]No keyword entered.[/yellow]")
             input("Press Enter to continue...")
             return
        keyword = keyword.strip()
        log.info(f"Generating dorks for keyword: {keyword}")
        generate_keyword_dorks(keyword)

    input("Press Enter to continue...")

def generate_domain_dorks(domain):
    # Print statements only, no logging needed here unless desired
    console.print(f"\n[green]--- Google Dorks for Domain: {domain} ---[/green]")
    google_dorks = [
        f'site:{domain}',
        f'site:{domain} intitle:"index of" | inurl:"index of" ',
        f'site:{domain} ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:sql',
        f'site:{domain} inurl:login | inurl:signin | intitle:"Login" | intitle:"Sign in"',
        f'site:{domain} inurl:admin | intitle:"Admin"',
        f'site:{domain} inurl:config | inurl:env | inurl:setting',
        f'site:{domain} "error" | "warning" | "SQL syntax" | "mysql_connect" | "pg_connect"',
        f'site:{domain} ext:pdf | ext:docx | ext:xlsx | ext:pptx "confidential"',
        f'site:{domain} inurl:wp-admin | inurl:wp-content | inurl:wp-includes',
        f'site:{domain} ext:php | ext:asp | ext:aspx | ext:jsp | ext:cfm intext:"password"',
        f'site:{domain} inurl:"/phpinfo.php" | intitle:"phpinfo()"',
        f'site:{domain} inurl:".git" | inurl:".svn" | inurl:".hg" -github.com',
        f'site:{domain} intext:"api_key" | intext:"apikey" | intext:"client_secret"',
    ]
    for dork in google_dorks:
        console.print(f"- {dork}")

    console.print(f"\n[green]--- GitHub Dorks for Domain: {domain} ---[/green]")
    github_dorks = [
        f'"{domain}" password | pass | login | secret | key | api_key | apikey',
        f'"{domain}" filename:.env | filename:.bash_history | filename:.passwd | filename:id_rsa',
        f'"{domain}" filename:config | filename:settings | filename:prod.yml | filename:prod.json',
        f'"{domain}" "Authorization: Bearer" | "Authorization: Basic"',
        f'"{domain}" ssh-rsa',
        f'"{domain}" -----BEGIN RSA PRIVATE KEY-----',
        f'"{domain}" filename:*.sql | filename:*.bak "password"',
    ]
    for dork in github_dorks:
        console.print(f"- {dork}")

def generate_keyword_dorks(keyword):
    # Print statements only
    console.print(f"\n[green]--- Google Dorks for Keyword: '{keyword}' ---[/green]")
    google_dorks = [
        f'"{keyword}" intitle:"index of" | inurl:"index of" ',
        f'"{keyword}" ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:sql',
        f'"{keyword}" inurl:login | inurl:signin | intitle:"Login" | intitle:"Sign in"',
        f'"{keyword}" inurl:admin | intitle:"Admin"',
        f'"{keyword}" "error" | "warning" | "SQL syntax" | "mysql_connect" | "pg_connect"',
        f'"{keyword}" ext:pdf | ext:docx | ext:xlsx | ext:pptx "confidential"',
        f'"{keyword}" intext:"password" | intext:"secret" | intext:"api_key"',
    ]
    for dork in google_dorks:
        console.print(f"- {dork}")

    console.print(f"\n[green]--- GitHub Dorks for Keyword: '{keyword}' ---[/green]")
    github_dorks = [
        f'"{keyword}" password | secret | api_key | credential',
        f'"{keyword}" filename:.env | filename:.log | filename:config | filename:settings',
        f'"{keyword}" language:sql | language:python | language:java | language:javascript "password"',
    ]
    for dork in github_dorks:
        console.print(f"- {dork}")

# --- IP Geolocation Lookup --- #
def run_geoip_lookup():
    """Looks up geolocation information for an IP address or domain."""
    log.info("Starting IP Geolocation utility.")
    console.print("\n[cyan]--- IP Geolocation Lookup ---[/cyan]")
    target_ip_or_domain = questionary.text("Enter the IP address or domain name:").ask()

    if target_ip_or_domain is None or not target_ip_or_domain.strip():
        log.warning("GeoIP lookup cancelled or empty input.")
        console.print("[yellow]No IP or domain entered.[/yellow]")
        input("Press Enter to continue...")
        return

    target = target_ip_or_domain.strip()
    log.debug(f"Looking up GeoIP for target: {target}")

    try:
        import requests
    except ImportError:
        log.error("GeoIP lookup requires 'requests' library.")
        console.print("[red]Error: Requires 'requests' library. Run: pip install requests[/red]")
        input("Press Enter to continue...")
        return

    api_url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    log.debug(f"Querying GeoIP API: {api_url}")
    console.print(f"[grey50]Querying ip-api.com for: {target}...[/grey50]")

    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get('status') == 'success':
            log.info(f"GeoIP lookup successful for {data.get('query')}")
            console.print(f"\n[green]Geolocation Information for {data.get('query')}:[/green]")
            info_map = {
                "IP Address": data.get('query'),
                "Country": data.get('country'),
                "Region": data.get('regionName'),
                "City": data.get('city'),
                "ZIP Code": data.get('zip'),
                "Latitude": data.get('lat'),
                "Longitude": data.get('lon'),
                "ISP": data.get('isp'),
                "Organization": data.get('org'),
                "AS Number/Name": data.get('as')
            }
            for key, value in info_map.items():
                if value:
                    console.print(f"  - [bold magenta]{key}:[/bold magenta] {value}")
        else:
            api_message = data.get('message', 'Unknown error from ip-api.com')
            log.warning(f"GeoIP API returned status '{data.get('status')}' for target {target}. Message: {api_message}")
            console.print(f"[red]API Error: {api_message}[/red]")
            if "Private range" in api_message:
                 console.print("[yellow]Cannot geolocate private/reserved IP addresses.[/yellow]")
            elif "Invalid query" in api_message:
                 console.print(f"[yellow]The input '{target}' might be an invalid IP or domain.[/yellow]")

    except requests.exceptions.Timeout:
        log.error(f"Request timed out connecting to ip-api.com for {target}")
        console.print("[red]Error: Request timed out connecting to ip-api.com.[/red]")
    except requests.exceptions.RequestException as e:
        log.exception(f"Error connecting to GeoIP API for {target}")
        console.print(f"[red]Error connecting to GeoIP API: {e}[/red]")
    except json.JSONDecodeError as e: # Catch JSON errors
        log.exception(f"Error decoding JSON response from GeoIP API for {target}")
        console.print(f"[red]Error decoding API response: {e}[/red]")
    except Exception as e:
        log.exception(f"An unexpected error occurred during GeoIP lookup for {target}")
        console.print(f"[red]An unexpected error occurred: {e}[/red]")

    input("Press Enter to continue...") 