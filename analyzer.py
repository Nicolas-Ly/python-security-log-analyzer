from collections import Counter
import json

# Load the threat feed from a file and return a dictionary of domain to severity
def load_threat_feed(file_path):
    threat_feed = {}

    try:
        with open(file_path, "r") as threat_file:
            for line_number, line in enumerate(threat_file, start=1):
                line = line.strip()

                if not line:
                    continue

                parts = line.split(",")

                if len(parts) != 2:
                    print(f"Skipping invalid threat feed line {line_number}: {line}")
                    continue

                threat_domain = parts[0].strip()
                severity = parts[1].strip().lower()

                if not threat_domain or not severity:
                    print(f"Skipping incomplete threat feed line {line_number}: {line}")
                    continue

                threat_feed[threat_domain] = severity

    except FileNotFoundError:
        print(f"Error: Threat feed file not found: {file_path}")
    except Exception as e:
        print(f"Error reading threat feed file: {e}")

    return threat_feed

# Analyze DNS logs and identify any suspicious domains based on the threat feed
def analyze_dns_logs(file_path, threat_feed):
    domains = []
    dns_alerts = []

    try:
        with open(file_path, "r") as dns_file:
            for line_number, line in enumerate(dns_file, start=1):
                parts = line.split()

                if len(parts) < 4:
                    print(f"Skipping malformed DNS log line {line_number}: {line.strip()}")
                    continue

                if "client=" not in parts[2] or "query=" not in parts[3]:
                    print(f"Skipping unexpected DNS format on line {line_number}: {line.strip()}")
                    continue

                try:
                    client = parts[2].split("=", 1)[1]
                    dns_domain = parts[3].split("=", 1)[1]
                except IndexError:
                    print(f"Skipping broken DNS key/value data on line {line_number}: {line.strip()}")
                    continue

                domains.append(dns_domain)

                if dns_domain in threat_feed:
                    dns_alerts.append({
                        "client": client,
                        "domain": dns_domain,
                        "severity": threat_feed[dns_domain],
                        "type": "dns"
                    })

    except FileNotFoundError:
        print(f"Error: DNS log file not found: {file_path}")
        return Counter(), []
    except Exception as e:
        print(f"Error reading DNS log file: {e}")
        return Counter(), []

    counts = Counter(domains)
    found_suspicious = False

    print("DNS Analysis")
    for domain, count in counts.items():
        print(domain, ":", count)

        if domain in threat_feed:
            print("ALERT: Suspicious Domain Detected:", domain, "| Severity:", threat_feed[domain])
            found_suspicious = True

        if count > 3:
            print("Possible DNS beaconing:", domain)

    if not found_suspicious:
        print("No suspicious domains found.")

    return counts, dns_alerts

# Analyze proxy logs and identify any malicious URLs based on the threat feed
def analyze_proxy_logs(file_path, threat_feed):
    proxy_alerts = []
    malicious_url_counts = Counter()

    print("\n=== Proxy Analysis ===")

    try:
        with open(file_path, "r") as proxy_file:
            for line_number, line in enumerate(proxy_file, start=1):
                parts = line.split()

                if len(parts) < 4:
                    continue

                if "user=" not in parts[2] or "url=" not in parts[3]:
                    continue

                user = parts[2].split("=", 1)[1]
                url = parts[3].split("=", 1)[1]

                for bad_domain, severity in threat_feed.items():
                    if bad_domain in url:
                        proxy_alerts.append({
                            "user": user,
                            "url": url,
                            "severity": severity,
                            "type": "proxy"
                        })
                        malicious_url_counts[(url, severity)] += 1

    except FileNotFoundError:
        print(f"Error: Proxy log file not found: {file_path}")
        return []

    if proxy_alerts:
        for (url, severity), count in malicious_url_counts.items():
            print(
                f"ALERT: Malicious proxy traffic: {url} "
                f"| Severity: {severity} | Count: {count}"
            )
    else:
        print("No malicious proxy activity found.")

    return proxy_alerts

# Generate a report summarizing the findings and write it to a file
def write_report(report_path, counts, dns_alerts, proxy_alerts):
    try:
        with open(report_path, "w") as report:
            report.write("Security Analysis Report\n")
            report.write("------------------------\n")

            report.write("DNS:\n")
            report.write("------------------------\n")

            if dns_alerts:
                for alert in dns_alerts:
                    report.write(
                        f"Client: {alert['client']} Queried: {alert['domain']} | "
                        f"Severity: {alert['severity']}\n"
                    )
            else:
                report.write("No suspicious DNS activity found.\n")

            for domain, count in counts.items():
                if count > 3:
                    report.write(f"Possible DNS Beaconing: {domain}\n")

            report.write("\nProxy:\n")
            report.write("------------------------\n")

            if proxy_alerts:
                for alert in proxy_alerts:
                    report.write(
                        f"User: {alert['user']} Accessed: {alert['url']} | "
                        f"Severity: {alert['severity']}\n"
                    )
            else:
                report.write("No malicious proxy activity found.\n")

        print(f"Report written to {report_path}")

    except Exception as e:
        print(f"Error writing report: {e}")

# Export results to JSON for potential use in a web dashboard or further analysis
def export_to_json(file_path, counts, dns_alerts, proxy_alerts):
    results = {
        "dns_counts": dict(counts),
        "dns_alerts": dns_alerts,
        "proxy_alerts": proxy_alerts
    }

    try:
        with open(file_path, "w") as json_file:
            json.dump(results, json_file, indent=4)

        print(f"Results exported to {file_path}")

    except Exception as e:
        print(f"Error exporting JSON: {e}")

# Main function to orchestrate the loading of the threat feed, analyzing logs, and generating reports
def main():
    threat_feed = load_threat_feed("logs/threat_feed.txt")

    if not threat_feed:
        print("No valid threat feed entries loaded. Exiting.")
        return

    counts, dns_alerts = analyze_dns_logs("logs/dns.log", threat_feed)
    proxy_alerts = analyze_proxy_logs("logs/proxy.log", threat_feed)

    write_report("report.txt", counts, dns_alerts, proxy_alerts)
    export_to_json("results.json", counts, dns_alerts, proxy_alerts)

# Entry point of the script
if __name__ == "__main__":
    main()