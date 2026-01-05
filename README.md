# Neutron-ng

**Advanced Reconnaissance Engine** for security researchers and penetration testers.

## Features

- **Subdomain Enumeration**: 12+ passive sources + active DNS resolution
- **URL Discovery**: Historical archives (Wayback, CommonCrawl, AlienVault)
- **JavaScript Analysis**: Endpoint extraction, secret detection
- **Technology Fingerprinting**: Identify web stack, frameworks, CDNs
- **Network Intelligence**: ASN, IP ranges, reverse DNS
- **Username OSINT**: Social media profile discovery
- **ProjectDiscovery Integration**: subfinder, naabu, httpx, katana pipeline
- **Deep Vulnerability Scanner**: XSS, SQLi detection with async crawling
- **Interactive Mode**: 15+ reconnaissance capabilities

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/Alerrrt/Neutron-ng.git
cd Neutron-ng

# Build release binary
cargo build --release

# Binary location
./target/release/neutron-ng
```

### Basic Usage

```bash
# Interactive mode
neutron-ng

# Quick scan
neutron-ng scan -t example.com -o ./results

# Subdomain enumeration
neutron-ng subdomains -t example.com

# Multiple targets
neutron-ng scan -t example.com,test.com -o ./output
```

## Configuration

Create `.env` file for API keys (optional but recommended):

```bash
cp .env.example .env
# Edit .env with your API keys
```

**Supported API Keys:**
- `NEUTRON_VIRUSTOTAL_API_KEY` - Enhanced subdomain enumeration
- `NEUTRON_SECURITYTRAILS_API_KEY` - DNS intelligence
- `NEUTRON_CHAOS_API_KEY` - ProjectDiscovery passive DNS

## Interactive Mode

Run `neutron-ng` without arguments to access the interactive dashboard with 15 capabilities:

- Subdomain Discovery (passive/active)
- URL & Endpoint Discovery
- JavaScript Analysis
- Secret Scanning
- DNS Records
- Technology Fingerprinting
- Network Intelligence
- Username OSINT
- IP Geolocation
- AI-Powered Scanning
- Deep Vulnerability Scan
- ProjectDiscovery Pipeline
- Configuration & Setup

## Output Structure

```
results/
└── example.com/
    └── 20260105_130000/
        ├── 01_subdomains/
        ├── 02_ports/
        ├── 03_http/
        ├── 04_crawl/
        ├── 05_vuln_scan/
        └── scan_metadata.json
```

## ProjectDiscovery Pipeline

Automated 4-phase reconnaissance workflow:

```
subfinder → naabu → httpx → katana
```

Discovers subdomains, scans ports, probes HTTP services, and crawls endpoints.

## Requirements

- **Rust**: 1.70+ 
- **Optional Tools**: subfinder, naabu, httpx, katana (for PD pipeline)

## License

MIT License - See [LICENSE](LICENSE) file

## Disclaimer

This tool is for authorized security testing only. Users are responsible for compliance with applicable laws.

## Contributing

Contributions welcome! Please open issues or submit pull requests.

---

**Built with Rust** | **Async/Concurrent** | **Modular Architecture**
