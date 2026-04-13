# Python DNS and Proxy Log Analyzer

## Overview

This project is a personal Python security lab that analyzes simulated DNS and proxy logs to detect suspicious domain activity, possible DNS beaconing, and malicious web traffic.

The goal of this project is to practice:

* Python scripting
* Log parsing
* Security analysis
* Basic threat detection logic
* Report generation

The script reads log files, identifies suspicious behavior, prints alerts, and generates a report.

---

## Features

* Parses DNS log entries
* Counts domain query frequency
* Detects suspicious domains from a watchlist
* Flags possible DNS beaconing (high-frequency queries)
* Parses proxy log entries
* Detects malicious proxy traffic
* Generates a `report.txt` with findings

---

## Project Structure

```
python-security-log-analyzer/
│
├── analyzer.py
├── report.txt
└── logs/
    ├── dns.log
    └── proxy.log
    └── threat_feed.txt
```

---

## How It Works

### DNS Log Analysis

* Reads `dns.log`
* Extracts queried domains
* Counts how often each domain appears
* Detects:

  * Known suspicious domains
  * Repeated queries (possible beaconing)

---

### Proxy Log Analysis

* Reads `proxy.log`
* Extracts accessed URLs
* Checks if URLs contain suspicious domains
* Flags malicious traffic

---

### Report Generation

* Writes findings to `report.txt`
* Separates results into:

  * DNS findings
  * Proxy findings

---

## Detection Logic

The script currently uses a simulated watchlist within a file called threat_feed.txt:

```
malicious-domain.ru
strange-domain.xyz
...
```

These are used to:

* Detect suspicious DNS queries
* Identify malicious proxy traffic

---

## Example Output

```
google.com : 3
malicious-domain.ru : 2
strange-domain.xyz : 1

ALERT: Suspicious domain detected: malicious-domain.ru

Now analyzing Proxy Logs...

URL Accessed: http://example.com
URL Accessed: http://malicious-domain.ru/payload

Looking for malicious traffic:

ALERT: Malicious proxy traffic: http://malicious-domain.ru/payload
```

---

## Requirements

* Python 3.x
* Uses built-in Python modules only (`collections`)

---

## How to Run

From the project directory:

```
python analyzer.py
```

---

## Skills Demonstrated

* Python file handling
* String parsing and manipulation
* Lists and loops
* Using `Counter` for frequency analysis
* Writing detection logic
* Security log analysis
* Report generation

---

## Use Case

This project simulates a basic security operations workflow where DNS and proxy logs are analyzed to detect potential threats.

It reflects common tasks performed by:

* SOC analysts
* Security engineers
* Incident responders

---

## Future Improvements

* Move suspicious domains to an external threat feed file (Now Implemented)
* Add severity levels (low, medium, high) (Now Implemented)
* Refactor into modular functions (Now Implemented)
* Export results as JSON or CSV
* Track client IPs and users
* Integrate real threat intelligence APIs
* Improve error handling

---

## Notes

This project uses simulated logs and hardcoded domains for practice.

---

## Author

Nicolas Lynch
