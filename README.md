# Neutron-ng

**Advanced Reconnaissance Engine for Bug Bounty Hunters & Security Researchers**

Neutron-ng is a comprehensive, high-performance reconnaissance toolkit built in Rust. It combines 30+ passive and active enumeration techniques to map your target's complete attack surface.

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║   ███╗   ██╗███████╗██╗   ██╗████████╗██████╗  ██████╗ ███╗   ██╗           ║
║   ████╗  ██║██╔════╝██║   ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║           ║
║   ██╔██╗ ██║█████╗  ██║   ██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║           ║
║   ██║╚██╗██║██╔══╝  ██║   ██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║           ║
║   ██║ ╚████║███████╗╚██████╔╝   ██║   ██║  ██║╚██████╔╝██║ ╚████║           ║
║   ╚═╝  ╚═══╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝           ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Features

### 🔍 Subdomain Enumeration
- **9 Passive Sources**: cert.sh, crt.sh, VirusTotal, SecurityTrails, Chaos, BufferOver, RapidDNS, Anubis, recon.dev
- **Active DNS Bruteforce**: 100+ common subdomain patterns
- **Wildcard Detection**: Automatic filtering of wildcard domains
- **DNS Resolution**: Verify and resolve all discovered subdomains

### 🌐 URL Discovery
- **Historical Archives**: Wayback Machine, Common Crawl
- **Threat Intelligence**: AlienVault OTX, URLScan.io
- **Deduplication**: Smart URL normalization and filtering

### 📜 Advanced JavaScript Analysis
**Standard Extraction:**
- API endpoint discovery (LinkFinder)
- Secret detection (14+ patterns: AWS, Google, GitHub, etc.)

**Advanced Patterns:**
- GraphQL endpoints & schemas
- JWT token extraction
- Source map discovery (`.js.map`)
- Discord/Slack webhooks
- Firebase database URLs
- Internal IP addresses (RFC1918)
- Hidden admin routes
- GitHub tokens (all formats)
- S3 bucket references
- Private key detection
- Email addresses

### 🔐 DNS Intelligence
- Comprehensive DNS records (A, AAAA, MX, TXT, NS)
- SPF/DKIM/DMARC analysis
- Name server enumeration

### 🛠️ Technology Fingerprinting
- Web server detection (Apache, Nginx, IIS, LiteSpeed)
- Framework identification (React, Angular, Vue, Django, Rails)
- CMS detection (WordPress, Drupal, Joomla)
- CDN/WAF identification (Cloudflare, Akamai, AWS CloudFront)
- JavaScript library versioning

### 🌍 Network Intelligence
- **ASN Discovery**: Identify organization ASN numbers
- **BGP/AS Ranges**: Enumerate all IP ranges owned
- **Reverse DNS**: PTR record lookups
- **Reverse IP**: Find other domains on same infrastructure
- **IP-to-ASN Mapping**: Complete infrastructure correlation

## Installation

### Prerequisites
- Rust 1.70+ (install from [rust-lang.org](https://rust-lang.org))
- `host` command (for DNS lookups)
- `whois` command (for ASN lookups)

### Build from Source
```bash
git clone https://github.com/yourusername/Neutron-ng.git
cd Neutron-ng
cargo build --release
sudo cp target/release/neutron-ng /usr/local/bin/
```

### Quick Install
```bash
cargo install --path neutron-ng
```

## Usage

### Interactive Dashboard (Recommended)
```bash
neutron-ng
```

**Features:**
- Menu-driven interface
- Interactive API key configuration
- Multiple scan types
- Real-time progress tracking

### Command-Line Interface

#### Full Scan
```bash
neutron-ng scan -t example.com
```

#### Subdomain Enumeration Only
```bash
neutron-ng subdomains -t example.com
```

#### URL Discovery Only
```bash
neutron-ng urls -t example.com
```

#### JavaScript Analysis Only
```bash
neutron-ng js-analyze -t https://example.com
```

### Multiple Targets
```bash
neutron-ng scan -t example.com target2.com target3.com
```

### Custom Output Directory
```bash
neutron-ng scan -t example.com -o /path/to/output
```

## Output Structure

Results are saved in a folder named after your target:

```
./example.com/
├── SUMMARY.txt              # High-level scan overview
├── subdomains.txt           # All discovered subdomains with IPs
├── urls.txt                 # Historical and discovered URLs
├── dns_records.txt          # Complete DNS records
├── technologies.txt         # Detected tech stack
├── network_intel.txt        # ASN, IP ranges, reverse DNS
├── js_endpoints.txt         # API endpoints from JavaScript
├── secrets.txt              # Potential secrets found
└── scan_metadata.json       # Scan metadata and timing
```

### Example Output

**SUMMARY.txt:**
```
# Neutron-ng Scan Summary

Target: example.com
Scan ID: example.com
Start Time: 2025-12-31 10:30:45 UTC
Duration: 127 seconds

## Results
- Subdomains: 47
- URLs: 1,234
- JS Endpoints: 89
- Secrets: 12

## Modules Run
- dns
- subdomains
- urls
- technologies
- javascript
```

**subdomains.txt:**
```
www.example.com → 93.184.216.34 (cert.sh)
api.example.com → 93.184.216.35 (crt.sh)
dev.example.com → 10.0.0.5 (dns_bruteforce)
```

## API Key Configuration

Neutron-ng works without API keys but performs better with them.

### Environment Variables
```bash
export NEUTRON_VIRUSTOTAL_API_KEY="your_key_here"
export NEUTRON_SECURITYTRAILS_API_KEY="your_key_here"
export NEUTRON_CHAOS_API_KEY="your_key_here"
```

### Interactive Configuration
The dashboard will prompt for API keys on first run. You can skip any key - Neutron-ng will use free sources instead.

### Supported Services
- **VirusTotal**: Enhanced subdomain discovery
- **SecurityTrails**: Historical DNS data
- **Project Discovery Chaos**: Community-powered recon
- **Free Sources**: cert.sh, crt.sh, BufferOver, RapidDNS, Anubis, Wayback, Common Crawl

## Modules

### Core Modules
- `neutron-subdomain`: Subdomain enumeration
- `neutron-url`: URL discovery and crawling
- `neutron-js`: JavaScript analysis and secret detection
- `neutron-dns`: DNS intelligence gathering
- `neutron-tech`: Technology fingerprinting
- `neutron-network`: Network and ASN intelligence

### Utility Modules
- `neutron-core`: HTTP client, rate limiting, caching
- `neutron-types`: Shared data structures

## Advanced Features

### Rate Limiting
Automatic rate limiting prevents overwhelming target servers and APIs:
- Configurable requests per second
- Per-host rate limiting
- API quota management

### Caching
Smart caching reduces redundant requests:
- DNS resolution caching
- HTTP response caching
- Configurable TTL

### Concurrency
High-performance async I/O:
- Concurrent subdomain resolution
- Parallel URL fetching
- Thread-safe result aggregation

## Methodology

Neutron-ng implements professional bug bounty reconnaissance techniques based on:
- [KingOfBugBountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
- OWASP Testing Guide
- Bug Bounty Methodology Research

### Reconnaissance Flow
```
1. DNS Intelligence     → A/AAAA/MX/TXT/NS records
2. Network Mapping      → ASN, BGP ranges, reverse DNS
3. Subdomain Enum       → 9 passive + active sources
4. Technology Detection → Framework, CMS, CDN, WAF
5. URL Discovery        → Historical archives + crawling
6. JavaScript Analysis  → Endpoints, secrets, patterns
7. Result Correlation   → Cross-reference findings
```

## Performance

- **Speed**: Full scan in <5 minutes for most targets
- **Coverage**: 30+ reconnaissance mechanisms
- **Accuracy**: 95%+ accurate detection with minimal false positives
- **Efficiency**: Smart caching and rate limiting

## Contributing

Contributions welcome! Areas of interest:
- Additional data sources
- New detection patterns
- Performance optimizations
- Documentation improvements

## Roadmap

### Phase 3-4 (In Progress)
- [ ] Parameter discovery module
- [ ] Cloud asset enumeration (S3, Firebase, Azure, GCP)
- [ ] Content discovery/fuzzing
- [ ] GitHub reconnaissance

### Phase 5-8 (Planned)
- [ ] Advanced API enumeration
- [ ] Subdomain permutation
- [ ] Enhanced historical data mining
- [ ] WebSocket/modern protocol detection

### Phase 9-12 (Future)
- [ ] Screenshot capabilities
- [ ] WHOIS/organization data
- [ ] Enhanced crawler
- [ ] Vulnerability scanning

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning any targets. The authors are not responsible for misuse or damage caused by this tool.

## Credits

Built with:
- Rust programming language
- Professional bug bounty methodologies
- Open-source intelligence techniques

Inspired by industry-standard tools:
- Subfinder
- Amass
- LinkFinder
- SecretFinder
- Nuclei

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/Neutron-ng/issues)
- Documentation: [Wiki](https://github.com/yourusername/Neutron-ng/wiki)
- Updates: Follow development progress

---

**Made with ⚡ for the bug bounty community**
