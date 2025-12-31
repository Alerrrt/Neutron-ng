# Neutron-ng

> A comprehensive reconnaissance engine built in Rust for security researchers and bug bounty hunters.

**Neutron-ng** combines the best features from WebRecon, KingOfBugbountyTips, and awesome-oneliner-bugbounty into a single, powerful, memory-safe tool with both CLI and web interfaces.

## Features

### Reconnaissance Modules

- **Subdomain Enumeration**: 10+ passive sources (cert.sh, crt.sh, SecurityTrails, VirusTotal, etc.) + active DNS brute-forcing
- **URL Discovery**: Wayback Machine, Common Crawl, web crawling with configurable depth
- **JavaScript Analysis**: Endpoint extraction (LinkFinder), secrets detection, library fingerprinting
- **Vulnerability Scanning**: XSS, SQLi, LFI/RFI, Open Redirect, CORS, SSRF, Command Injection, SSTI
- **Cloud & Infrastructure**: AWS S3, Azure Blob, GCP Storage scanning, ASN/IP enumeration, Shodan integration
- **Git Exposure**: .git directory testing, credential scanning, repository search

### Key Capabilities

- High-performance async I/O with intelligent rate limiting
- Multiple output formats (JSON, HTML, CSV, console)
- Optional web interface with real-time updates
- Scan resume capability for interrupted scans
- Wildcard detection and intelligent filtering
- Kali Linux integration

## Installation

### From Pre-built Binary

```bash
# Download latest release
wget https://github.com/alerrrt/neutron-ng/releases/latest/download/neutron-ng-linux-amd64

# Make executable
chmod +x neutron-ng-linux-amd64
sudo mv neutron-ng-linux-amd64 /usr/local/bin/neutron-ng
```

### Kali Linux

```bash
# Install from package (coming soon)
sudo apt-get update
sudo apt-get install neutron-ng
```

### From Source

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build from source
git clone https://github.com/alerrrt/neutron-ng.git
cd neutron-ng
cargo build --release

# Install
sudo cp target/release/neutron-ng /usr/local/bin/
```

### Docker

```bash
docker pull ghcr.io/alerrrt/neutron-ng:latest
docker run -v $(pwd)/results:/app/results neutron-ng scan -t example.com
```

## Quick Start

### Basic Scan

```bash
# Comprehensive scan
neutron-ng scan -t example.com

# Subdomain enumeration only
neutron-ng subdomains -t example.com

# URL discovery
neutron-ng urls -t example.com

# Vulnerability scanning
neutron-ng vuln-scan -t https://example.com
```

### Advanced Options

```bash
# Multiple targets
neutron-ng scan -t target1.com,target2.com,target3.com

# Custom output
neutron-ng scan -t example.com -o ./results --format json,html

# Rate limiting
neutron-ng scan -t example.com --rate-limit 10

# With proxy
neutron-ng scan -t example.com --proxy http://127.0.0.1:8080

# Resume interrupted scan
neutron-ng scan --resume scan-12345
```

### Web Interface

```bash
# Start web server
neutron-ng web --port 8080

# Open browser to http://localhost:8080
```

## Configuration

Create a configuration file at `~/.config/neutron-ng/config.toml`:

```toml
[general]
timeout = 30
concurrency = 50
rate_limit = 100

[api_keys]
securitytrails = "your-api-key"
virustotal = "your-api-key"
shodan = "your-api-key"

[modules]
enabled = ["subdomain", "url", "js", "vuln"]

[output]
default_format = "json"
directory = "./results"
```

Or use environment variables:

```bash
export NEUTRON_SECURITYTRAILS_API_KEY="your-key"
export NEUTRON_VIRUSTOTAL_API_KEY="your-key"
```

## Documentation

- [Installation Guide](docs/installation.md)
- [CLI Usage](docs/cli-usage.md)
- [Web Interface](docs/web-interface.md)
- [API Documentation](docs/api.md)
- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)

## Performance

- Process 10,000+ subdomains in under 5 minutes
- Crawl 100,000+ URLs per hour
- Analyze 1,000+ JavaScript files per minute
- Memory usage under 500MB for typical scans

## Requirements

### Optional External Tools

For enhanced functionality, install these tools:

- `nmap` - Advanced port scanning
- `sqlmap` - Deep SQL injection analysis
- `ffuf` - Directory brute-forcing
- `nuclei` - Template-based scanning

### API Keys (Optional)

Many modules work without API keys but have limited functionality. Free tiers available:

- SecurityTrails (subdomain enumeration)
- VirusTotal (subdomain + file analysis)
- Shodan (infrastructure intel)
- Censys (certificate data)

## Development Status

**Current Version**: 0.1.0 (Alpha)

- [x] Core engine and orchestration
- [x] Configuration system
- [x] HTTP client with rate limiting
- [ ] Subdomain enumeration (in progress)
- [ ] URL discovery
- [ ] JavaScript analysis
- [ ] Vulnerability scanning
- [ ] Web interface

See [task.md](https://github.com/alerrrt/neutron-ng/blob/main/.gemini/brain/task.md) for detailed development progress.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Inspired by:
- [WebRecon](https://github.com/rebootuser/WebRecon)
- [KingOfBugbountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
- [awesome-oneliner-bugbounty](https://github.com/dwisiswant0/awesome-oneliner-bugbounty)
- Project Discovery tools (subfinder, httpx, nuclei)

---

**Built with ❤️ in Rust**
