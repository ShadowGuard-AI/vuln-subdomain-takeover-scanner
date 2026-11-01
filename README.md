# vuln-Subdomain-Takeover-Scanner
Scans for potential subdomain takeover vulnerabilities by checking DNS records against common hosting providers. Each candidate's CNAME record is looked up (this needs dnspython), the CNAME target is mapped to a known provider, and the provider's HTTP fingerprint, read on any response status including 404, confirms the verdict: a body fingerprint alone, with no CNAME behind it, is never reported. A candidate whose CNAME points at a provider but which does not answer over HTTP is reported separately as a dangling candidate. Without -s, only the supplied domain itself is checked. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-subdomain-takeover-scanner`

## Usage
`./vuln-subdomain-takeover-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-s`: Path to a file containing a list of subdomains, one per line.
- `-t`: Number of threads to use (default: 10).
- `-v`: Enable verbose output.
- `-o`: Output file to write results to.

## License
Copyright (c) ShadowStrikeHQ
