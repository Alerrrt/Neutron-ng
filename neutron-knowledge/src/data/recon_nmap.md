# Nmap Reconnaissance

## Host Discovery
```bash
nmap -sn -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443 -PO --source-port 53 10.0.0.1/24
```

## Full TCP Scan
```bash
nmap -p- -sC -sV -O --min-rate=1000 -T4 -vv 10.0.0.1 -oA full_scan
```

## Fast UDP Scan
```bash
nmap -sU --top-ports 100 10.0.0.1
```

## NSE Scripts
```bash
nmap -sV --script=vuln 10.0.0.1
nmap -sV --script=http-enum 10.0.0.1
nmap --script=smb-vuln* -p 139,445 10.0.0.1
```
