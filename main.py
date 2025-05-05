import argparse
import logging
import requests
import socket
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common hosting providers and their takeover indicators
TAKEOVER_PROVIDERS = {
    "Heroku": "No such app",
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Amazon S3": "NoSuchBucket",
    "Fastly": "Please check that this domain has been added to a service.",
    "Pantheon": "The gods are angry.",
    "Cloudflare": "cloudflare",
    "Bitbucket": "Repository not found",
    "Help Scout": "No Such App",
    "Cargo Collective": "If you're moving your domain away from Cargo you must",
    "Unbounce": "The requested URL was not found on this server."
}

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans for potential subdomain takeover vulnerabilities.")
    parser.add_argument("domain", help="The target domain to scan.")
    parser.add_argument("-s", "--subdomains", help="Path to a file containing a list of subdomains, one per line.", required=False)
    parser.add_argument("-t", "--threads", help="Number of threads to use (default: 10)", type=int, default=10, required=False)
    parser.add_argument("-v", "--verbose", help="Enable verbose output.", action="store_true", required=False)
    parser.add_argument("-o", "--output", help="Output file to write results to.", required=False)
    return parser

def check_subdomain_takeover(subdomain):
    """
    Checks if a subdomain is vulnerable to takeover.
    Args:
        subdomain (str): The subdomain to check.
    Returns:
        str: The vulnerable provider if takeover is possible, None otherwise.
    """
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        content = response.text
        for provider, indicator in TAKEOVER_PROVIDERS.items():
            if indicator in content:
                logging.warning(f"Potential subdomain takeover vulnerability detected on {subdomain} for {provider}")
                return provider
        return None
    except requests.exceptions.RequestException as e:
        # Handle connection errors, timeouts, etc.
        logging.debug(f"Error connecting to {subdomain}: {e}")  # Debug level for connection errors
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking {subdomain}: {e}") # Generic Error Handling
        return None

def resolve_domain(domain):
    """
    Resolves a domain to its IP address.
    Args:
        domain (str): The domain to resolve.
    Returns:
        str: The IP address of the domain, or None if resolution fails.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        logging.warning(f"Could not resolve domain {domain}: {e}")
        return None

def read_subdomains_from_file(filename):
    """
    Reads subdomains from a file, one per line.
    Args:
        filename (str): The path to the file.
    Returns:
        list: A list of subdomains.
    """
    try:
        with open(filename, 'r') as f:
            subdomains = [line.strip() for line in f.readlines()]
        return subdomains
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        return None
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return None

def main():
    """
    Main function to execute the subdomain takeover scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target_domain = args.domain
    logging.info(f"Starting subdomain takeover scan for domain: {target_domain}")

    # Validate domain format
    if not isinstance(target_domain, str):
        logging.error("Invalid domain format. Please provide a valid string.")
        sys.exit(1)

    subdomains = []
    if args.subdomains:
        subdomains = read_subdomains_from_file(args.subdomains)
        if subdomains is None:
            sys.exit(1)
    else:
        # Default to scanning the main domain.
        subdomains = [target_domain]

    vulnerable_subdomains = {}

    for subdomain in subdomains:
        if not isinstance(subdomain, str):
                logging.warning(f"Skipping invalid subdomain: {subdomain}")
                continue

        logging.debug(f"Checking subdomain: {subdomain}")

        # Check if the subdomain resolves
        if resolve_domain(subdomain) is None:
            logging.debug(f"Subdomain {subdomain} does not resolve, skipping...")
            continue

        # Check for subdomain takeover
        provider = check_subdomain_takeover(subdomain)
        if provider:
            vulnerable_subdomains[subdomain] = provider

    if vulnerable_subdomains:
        logging.info("Vulnerable subdomains found:")
        for subdomain, provider in vulnerable_subdomains.items():
            logging.info(f"  - {subdomain}: Vulnerable to {provider} takeover")

        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write("Vulnerable Subdomains:\n")
                    for subdomain, provider in vulnerable_subdomains.items():
                        f.write(f"  - {subdomain}: Vulnerable to {provider} takeover\n")
                logging.info(f"Results written to: {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
    else:
        logging.info("No vulnerable subdomains found.")

if __name__ == "__main__":
    main()