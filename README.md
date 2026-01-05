# Neutron-ng

Neutron-ng is a professional, multi-modal reconnaissance and Open Source Intelligence (OSINT) suite designed for penetration testers and security researchers. It aggregates multiple data sources and attack vectors into a single, cohesive engine, enabling rapid and comprehensive infrastructure mapping.

## Features

*   **Hybrid Engine**: Orchestrates native Rust modules alongside industry-standard tools (Nuclei, Subfinder, Naabu, HTTPX, Katana).
*   **Multi-Modal Architecture**:
    *   **Domain**: Complete attack surface mapping (subdomains, ports, URLs, technologies, vulnerabilities).
    *   **User**: Cross-platform username presence detection (OSINT).
    *   **IP**: Geolocation, ASN, and network intelligence.
    *   **AI**: Intelligent vulnerability scanning using targeted natural language prompts.
*   **Knowledge Base**: Integrated security cheat sheets for quick reference.
*   **Performance**: Built on an asynchronous Rust core for high-throughput, non-blocking operations.
*   **Usability**: Features both a script-friendly CLI and an interactive Terminal UI (TUI).

## Installation

### Prerequisites
*   **Rust**: Stable toolchain (install via `rustup`).
*   **Go**: Required for external tool installation (Subfinder, Nuclei, etc.).

### Build from Source
```bash
git clone https://github.com/Alerrrt/Neutron-ng.git
cd Neutron-ng
cargo build --release
sudo cp target/release/neutron-ng /usr/local/bin/
```

### Dependency Setup
Neutron-ng automatically manages its external dependencies. Run the setup command to install or update the required ProjectDiscovery tools:
```bash
neutron-ng setup
```

## Usage

Neutron-ng supports both interactive and direct command-line usage.

### Interactive Mode
Run without arguments to launch the TUI menu:
```bash
neutron-ng
```

### Command Line Interface

**1. Domain Reconnaissance (Scan)**
Perform a full reconnaissance scan on a target domain. This includes subdomain enumeration, port scanning, URL discovery, and vulnerability analysis.
```bash
neutron-ng scan -t example.com
```

**2. Username OSINT**
Search for a username across 200+ social media and developer platforms.
```bash
neutron-ng user -t username
```

**3. IP Intelligence**
Analyze an IP address for geolocation, ASN, and network information.
```bash
neutron-ng ip -t 8.8.8.8
```

**4. AI-Driven Vulnerability Scan**
Use the AI engine to generate and run targeted vulnerability scans.
```bash
neutron-ng ai -t example.com --prompt "Find SQL injection vulnerabilities"
```

**5. Security Knowledge Base**
Access built-in cheat sheets and references.
```bash
neutron-ng cheat list                   # List available topics
neutron-ng cheat reverse_shells         # View specific cheat sheet
neutron-ng cheat --search "nmap"        # Search across all topics
```

## Architecture

Neutron-ng operates as a unified orchestrator:

| Component | Responsibility | Integrated Tools |
|-----------|----------------|------------------|
| **Core Engine** | Workflow management, concurrency, results storage | - |
| **neutron-subdomain** | Passive & Active subdomain enumeration | Subfinder |
| **neutron-network** | Port scanning, DNS resolution, IP intel | Naabu |
| **neutron-url** | URL discovery, probing, tech detection | HTTPX |
| **neutron-crawler** | Deep web crawling, JavaScript analysis | Katana |
| **neutron-js** | Secret scanning, endpoint extraction | - |
| **neutron-ai** | Intelligent vulnerability scanning | Nuclei |
| **neutron-user** | Username OSINT | - |

## Configuration
API keys and settings are managed via the configuration system. You will be prompted to enter keys (VirusTotal, SecurityTrails, Chaos) during your first scan if they are missing.

---
*Created for educational and professional security testing purposes only.*
