pub const PROMPTS: &[(&str, &str)] = &[
    (
        "RCE & Command Injection",
        "Find Remote Code Execution (RCE) vulnerabilities, command injection flaws, and blind OS command injection points."
    ),
    (
        "Authentication Bypass",
        "Detect authentication bypass vulnerabilities, broken access control, and privilege escalation headers."
    ),
    (
        "SQL Injection (SQLi)",
        "Scan for SQL injection vulnerabilities including error-based, time-based, and boolean-blind SQLi."
    ),
    (
        "Cross-Site Scripting (XSS)",
        "Identify Reflected and Stored Cross-Site Scripting (XSS) vulnerabilities and context-aware polyglots."
    ),
    (
        "Server-Side Request Forgery (SSRF)",
        "Find SSRF vulnerabilities, cloud metadata exposure, and internal port scanning capabilities."
    ),
    (
        "Sensitive Data Exposure",
        "Detect exposed configuration files, backup files, API keys, tokens, and PII leaks."
    ),
    (
        "CVE Specific (Recent Critical)",
        "Scan for recently disclosed critical CVEs (CVSS 9.0+) affecting web applications and infrastructure."
    ),
    (
        "Logic Flaws & Business Logic",
        "Identify potential business logic vulnerabilities, IDOR, and race conditions."
    ),
    (
        "WordPress Security",
        "Scan for WordPress vulnerabilities, exposed plugins, users, and configuration issues."
    ),
    (
        "API Security (REST/GraphQL)",
        "Check for broken object level authorization, mass assignment, and graphql introspection."
    )
];
