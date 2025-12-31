# Neutron-ng

Professional CLI reconnaissance tool for penetration testers and security professionals.

High-performance reconnaissance toolkit built in Rust, combining 30+ enumeration techniques to efficiently map target attack surfaces.

## Features

**Subdomain Enumeration**
- 9 passive sources: cert.sh, crt.sh, VirusTotal, SecurityTrails, Chaos, BufferOver, RapidDNS, Anubis, recon.dev
- Active DNS bruteforce with 100+ common patterns
- Wildcard detection and DNS resolution

**URL Discovery**
- Historical archives: Wayback Machine, Common Crawl
- Threat intelligence: AlienVault OTX, URLScan.io

**JavaScript Analysis**
- API endpoint discovery
- Secret detection (AWS, Google, GitHub tokens, etc.)
- GraphQL endpoint extraction
- JWT token detection
- Source map discovery
- Webhook detection (Discord, Slack)
- Internal IP extraction
- Hidden admin route discovery

**DNS Intelligence**
- Complete DNS records (A, AAAA, MX, TXT, NS)
- SPF/DKIM/DMARC analysis

**Technology Fingerprinting**
- Web server detection
- Framework identification
- CMS detection
- CDN/WAF identification

**Network Intelligence**
- ASN discovery
- BGP range enumeration
- Reverse DNS lookups
- IP-to-ASN mapping

## Installation

### Prerequisites
- Rust 1.70+
- `host` command
- `whois` command

### Build
```bash
git clone https://github.com/Alerrrt/Neutron-ng.git
cd Neutron-ng
cargo build --release
sudo cp target/release/neutron-ng /usr/local/bin/
```

## Usage

### Interactive Dashboard
```bash
neutron-ng
```

### Command Line

Full scan:
```bash
neutron-ng scan -t example.com
```

Subdomain enumeration only:
```bash
neutron-ng subdomains -t example.com
```

Multiple targets:
```bash
neutron-ng scan -t example.com target2.com target3.com
```

## Output

Results are saved in a folder named after your target:

```
./example.com/
├── SUMMARY.txt
├── subdomains.txt
├── urls.txt
├── dns_records.txt
├── technologies.txt
├── network_intel.txt
├── js_endpoints.txt
├── secrets.txt
└── scan_metadata.json
```

All output is in plain text format for easy integration with other tools.

## API Keys (Optional)

Set environment variables for enhanced functionality:

```bash
export NEUTRON_VIRUSTOTAL_API_KEY="your_key"
export NEUTRON_SECURITYTRAILS_API_KEY="your_key"
export NEUTRON_CHAOS_API_KEY="your_key"
```

Tool works without API keys using free sources.

## Integration

Pipe output to other tools:
```bash
neutron-ng subdomains -t example.com | nuclei -t cves/
neutron-ng scan -t target.com && cat target.com/urls.txt | httpx
```

## License

MIT License

## Disclaimer

For authorized security testing only. Always obtain proper authorization before scanning targets.
