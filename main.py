import argparse
import concurrent.futures
import logging
import sys

import requests

try:
    import dns.exception
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    dns = None
    HAS_DNSPYTHON = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Body fingerprints for providers, matched only as confirmation. A body
# fingerprint on its own never produces a takeover verdict: the CNAME
# evidence below decides, and the fingerprint confirms. (The old bare
# "cloudflare" body entry is dropped: a page merely mentioning Cloudflare
# is not takeover evidence.)
TAKEOVER_PROVIDERS = {
    "Heroku": "No such app",
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Amazon S3": "NoSuchBucket",
    "Fastly": "Please check that this domain has been added to a service.",
    "Pantheon": "The gods are angry.",
    "Bitbucket": "Repository not found",
    "Help Scout": "No Such App",
    "Cargo Collective": "If you're moving your domain away from Cargo you must",
    "Unbounce": "The requested URL was not found on this server."
}

# Provider CNAME suffixes: where a candidate's CNAME points is what makes
# it a takeover candidate for that provider.
CNAME_PROVIDERS = {
    "github.io": "GitHub Pages",
    "s3.amazonaws.com": "Amazon S3",
    "herokuapp.com": "Heroku",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "bitbucket.io": "Bitbucket",
    "helpscoutdocs.com": "Help Scout",
    "cargocollective.com": "Cargo Collective",
    "unbouncepages.com": "Unbounce"
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


def lookup_cname(host):
    """
    Look up a host's CNAME record.

    Args:
        host (str): The host to look up; any port or path is stripped.

    Returns:
        tuple: (cname target or None, lookup_completed). lookup_completed is
        False only when the lookup itself could not be performed (the DNS
        library is missing or the resolver failed); a completed lookup that
        finds no CNAME returns (None, True).
    """
    name = host.split("/")[0].split(":")[0]
    if not HAS_DNSPYTHON:
        logging.warning("dnspython is not available, so no CNAME lookup can be performed.")
        return None, False
    try:
        answers = dns.resolver.resolve(name, "CNAME")
        for answer in answers:
            return str(answer.target).rstrip("."), True
        return None, True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, True
    except Exception as e:
        logging.debug(f"CNAME lookup failed for {name}: {e}")
        return None, False


def provider_for_cname(cname):
    """Map a CNAME target to a known provider by suffix, or None."""
    if not cname:
        return None
    lowered = cname.lower().rstrip(".")
    for suffix, provider in CNAME_PROVIDERS.items():
        if lowered == suffix or lowered.endswith("." + suffix):
            return provider
    return None


def check_one(subdomain):
    """
    Check one candidate name.

    The verdict is driven by the CNAME: a candidate whose CNAME points at
    a known provider is vulnerable when that provider's fingerprint is
    served in the HTTP response body (on any status code, including 404),
    and is a dangling candidate when it cannot be reached over HTTP at
    all. Body fingerprints alone, with no CNAME behind them, never
    produce a verdict.

    Returns:
        dict: {subdomain, cname, provider, status, checked}, where status
        is "vulnerable", "dangling", or "clean".
    """
    cname, lookup_done = lookup_cname(subdomain)
    checked = lookup_done
    body = None
    try:
        # No raise_for_status: the GitHub Pages and S3 fingerprints are
        # served on 404 and error responses, and those bodies are read too.
        response = requests.get(f"http://{subdomain}", timeout=5)
        body = response.text
        checked = True
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error connecting to {subdomain}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking {subdomain}: {e}")

    provider = provider_for_cname(cname)
    result = {"subdomain": subdomain, "cname": cname, "provider": provider,
              "status": "clean", "checked": checked}
    if provider and body is not None and TAKEOVER_PROVIDERS.get(provider, "") in body:
        result["status"] = "vulnerable"
        logging.warning(f"Potential subdomain takeover vulnerability detected on {subdomain} for {provider} (CNAME: {cname})")
    elif provider and body is None:
        result["status"] = "dangling"
        logging.warning(f"Dangling candidate: {subdomain} has a CNAME to {provider} ({cname}) but no HTTP response.")
    return result


def check_subdomain_takeover(subdomain):
    """
    Checks if a subdomain is vulnerable to takeover.
    Args:
        subdomain (str): The subdomain to check.
    Returns:
        str: The vulnerable provider if takeover is possible, None otherwise.
    """
    result = check_one(subdomain)
    if result["status"] == "vulnerable":
        return result["provider"]
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
            subdomains = [line.strip() for line in f.readlines() if line.strip()]
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

    if args.threads < 1:
        logging.error("Invalid input: threads must be at least 1.")
        sys.exit(1)

    target_domain = args.domain
    logging.info(f"Starting subdomain takeover scan for domain: {target_domain}")

    if not isinstance(target_domain, str):
        logging.error("Invalid domain format. Please provide a valid string.")
        sys.exit(1)

    subdomains = []
    if args.subdomains:
        subdomains = read_subdomains_from_file(args.subdomains)
        if subdomains is None:
            sys.exit(1)
    else:
        # Without -s, only the supplied domain itself is checked.
        subdomains = [target_domain]

    if not subdomains:
        logging.error("No subdomains to check.")
        sys.exit(1)

    candidates = [s for s in subdomains if isinstance(s, str)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = list(pool.map(check_one, candidates))

    checked_count = sum(1 for r in results if r["checked"])
    vulnerable = {r["subdomain"]: r["provider"] for r in results if r["status"] == "vulnerable"}
    dangling = [r for r in results if r["status"] == "dangling"]

    if vulnerable:
        logging.info("Vulnerable subdomains found:")
        for subdomain, provider in vulnerable.items():
            logging.info(f"  - {subdomain}: Vulnerable to {provider} takeover")
    if dangling:
        logging.info("Dangling candidates (CNAME points at a provider, no HTTP response):")
        for r in dangling:
            logging.info(f"  - {r['subdomain']}: CNAME to {r['provider']} ({r['cname']})")
    if not vulnerable and checked_count > 0:
        logging.info("No vulnerable subdomains found.")
    logging.info(f"Checked {checked_count} of {len(candidates)} candidate names.")

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write("Subdomain Takeover Scan Results:\n")
                f.write(f"Checked: {checked_count} of {len(candidates)} candidate names.\n")
                f.write("Vulnerable Subdomains:\n")
                if vulnerable:
                    for subdomain, provider in vulnerable.items():
                        f.write(f"  - {subdomain}: Vulnerable to {provider} takeover\n")
                else:
                    f.write("  (none)\n")
                f.write("Dangling Candidates:\n")
                if dangling:
                    for r in dangling:
                        f.write(f"  - {r['subdomain']}: CNAME to {r['provider']} ({r['cname']})\n")
                else:
                    f.write("  (none)\n")
            logging.info(f"Results written to: {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")

    if checked_count == 0:
        logging.error("Nothing could be checked: no CNAME lookup completed and no HTTP response was received. The scan is inconclusive.")
        sys.exit(1)


if __name__ == "__main__":
    main()
