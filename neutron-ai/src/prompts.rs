pub const PROMPTS: &[(&str, &str)] = &[
    // XSS
    ("XSS: Basic Detection", "Find common XSS patterns in response bodies."),
    ("XSS: Reflected", "Identify reflected XSS vulnerabilities via GET parameters."),
    ("XSS: DOM-Based", "Find DOM-based XSS vulnerabilities where user input is reflected inside JavaScript execution."),
    ("XSS: Stored", "Identify stored XSS vulnerabilities where malicious scripts persist in the application."),
    ("XSS: WAF Bypass", "Identify XSS vulnerabilities that bypass common web application firewalls."),
    ("XSS: Event Handlers", "Scan for XSS vulnerabilities inside inline event handlers such as onmouseover, onclick."),

    // SQL Injection
    ("SQLi: Blind", "Use time-based techniques to find blind SQL injection."),
    ("SQLi: Error-Based", "Check for error messages revealing SQL queries."),
    ("SQLi: Union-Based", "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data."),
    ("SQLi: Boolean-Based", "Identify SQL injection vulnerabilities using boolean-based conditions."),
    ("SQLi: Second-Order", "Identify second-order SQL injection vulnerabilities where input is stored and executed later."),
    ("SQLi: Time-Based", "Detect SQL injection vulnerabilities using time delay techniques."),

    // RCE
    ("RCE: Basic Detection", "Find potential remote command execution in input fields."),
    ("RCE: Command Injection", "Identify potential command injection vulnerabilities in input fields."),
    ("RCE: File Upload", "Detect RCE vulnerabilities through insecure file upload mechanisms."),
    ("RCE: Unsafe Functions", "Identify unsafe function calls that may lead to remote command execution."),
    ("RCE: Upload Exploitation", "Scan for insecure file upload mechanisms that allow RCE."),

    // Directory Traversal
    ("LFI: Exploit Traversal", "Detect sensitive files exposed via traversal attacks."),
    ("LFI: Dot-Dot-Slash", "Identify directory traversal vulnerabilities allowing access to sensitive files."),
    ("LFI: Absolute Path", "Find vulnerabilities where absolute file paths can be exploited for unauthorized access."),
    ("LFI: Windows Path", "Identify directory traversal vulnerabilities using Windows-style file paths."),
    ("LFI: PHP Inclusion", "Check for traversal vulnerabilities allowing PHP file inclusion."),

    // Auth Bypass
    ("Auth: Weak Login", "Identify login pages vulnerable to authentication bypass."),
    ("Auth: JWT Tampering", "Identify authentication bypass vulnerabilities due to weak JWT token implementations."),
    ("Auth: API Key Exposure", "Detect weak or publicly exposed API keys leading to authentication bypass."),
    ("Auth: JWT Manipulation", "Scan for JWT vulnerabilities where authentication can be bypassed."),
    ("Auth: Weak OAuth", "Identify improperly configured OAuth authentication mechanisms."),

    // SSRF
    ("SSRF: Basic Detection", "Find SSRF vulnerabilities allowing remote server requests."),
    ("SSRF: Open Redirect", "Identify SSRF vulnerabilities that allow open redirection to attacker-controlled servers."),
    ("SSRF: Internal Scanning", "Detect internal port scanning vulnerabilities using SSRF payloads."),
    ("SSRF: Header Injection", "Identify SSRF vulnerabilities that exploit insecure header handling."),
    ("SSRF: Proxy Misconfig", "Scan for SSRF vulnerabilities enabled due to misconfigured proxy servers."),

    // Misconfiguration
    ("Config: General Issues", "Scan for default credentials, exposed directories, and insecure headers."),
    ("Config: Default Creds", "Scan for applications running with default credentials left unchanged."),
    ("Config: Insecure Headers", "Identify missing security headers such as CSP, X-Frame-Options, and HSTS."),
    ("Config: Public Admin", "Identify web applications exposing admin panels without authentication."),
    ("Config: Cloud Buckets", "Find cloud storage misconfigurations exposing sensitive data."),

    // Race Condition
    ("Race Condition", "Identify vulnerabilities where multiple parallel processes can manipulate shared resources."),

    // XXE
    ("XXE Detection", "Identify XML External Entity attacks in web applications accepting XML input."),

    // File Inclusion
    ("File Inclusion (LFI/RFI)", "Check for Local and Remote File Inclusion vulnerabilities in file upload and inclusion mechanisms."),

    // Request Smuggling
    ("HTTP Smuggling", "Find HTTP request smuggling vulnerabilities by testing different content-length and transfer encoding headers."),

    // Hardcoded Credentials
    ("Secrets: API Keys", "Scan for exposed API keys in source code, configuration files, and logs."),
    ("Secrets: DB Credentials", "Identify hardcoded database usernames and passwords in backend source code."),
    ("Secrets: SSH Keys", "Detect SSH private keys left in public repositories or web directories."),
    ("Secrets: JWT Secrets", "Identify hardcoded JSON Web Token (JWT) secrets that can be exploited for authentication bypass."),
    ("Secrets: Cloud Creds", "Scan for AWS, Google Cloud, and Azure credentials embedded in source files."),
    ("Secrets: Source Code Keys", "Detect hardcoded API keys left inside JavaScript, Python, and other language files."),
    ("Secrets: Config Passwords", "Scan for plaintext passwords stored in environment files and config files.")
];
