from collections import Counter

# function to load the threat feed
def load_threat_feed(file_path):
    threat_feed = {}

    threat_file = open(file_path, "r")

    for line in threat_file:
        line = line.strip()

        if line:
            parts = line.split(",")
            threat_domain = parts[0]
            severity = parts[1]
            threat_feed[threat_domain] = severity
    
    threat_file.close()
    return threat_feed

# function to analyze the DNS Logs for malicious domains
def analyze_dns_logs(file_path, threat_feed):
    domains = []

    dns_file = open(file_path, "r")

    for line in dns_file:
        parts = line.split()
        if len(parts) >= 4 and "query=" in parts[3]:
            dns_domain = parts[3].split("=")[1]
            domains.append(dns_domain)

    dns_file.close()

    counts = Counter(domains)
    found_suspicious = False

    print("DNS Analysis")

    for domain, count in counts.items():
        print(domain, ":", count)

        if domain in threat_feed:
            print("ALERT: Suspicious Domain Detected:", domain, "| Severity:", threat_feed[domain], "\n")
            found_suspicious = True

        if count > 3:
            print("Possible DNS beaconing:", domain, "\n")

    if not found_suspicious:
        print("No suspicious domains found.\n")

    return counts

# function to analyze proxy logs

def analyze_proxy_logs(file_path, threat_feed):
    urls = []
    print("Proxy Analysis:")
    proxy_file = open(file_path, "r")

    for line in proxy_file:
        parts = line.split()
        
        if len(parts) >= 4 and "url=" in parts[3]:
            url = parts[3].split("=")[1]
            urls.append(url)
            print("URL Accessed:", url)

    proxy_file.close()

    print("\nLooking for malicious traffic")
    for url in urls:
        for bad_domain in threat_feed.keys():
            if bad_domain in url:
                print("ALERT: Malicious proxy traffic:", url, "| Severity:", threat_feed[bad_domain])
    return urls


def write_report(report_path, counts, urls, threat_feed):
    report = open(report_path, "w")

    report.write("Security Analysis Report\n")
    report.write("------------------------\n")

    report.write("DNS:\n")
    report.write("------------------------\n")

    for domain, count in counts.items():
        if domain in threat_feed:
            report.write(f"Suspicious DNS Query:{domain} | Severity: {threat_feed[domain]}\n")

        if count > 3: 
            report.write(f"Possible DNS Beaconing: {domain}\n")
    
    report.write("\nProxy\n")
    report.write("------------------------\n")

    for url in urls:
        for bad_domain in threat_feed.keys():
            if bad_domain in url:
                report.write(f"Malicious Proxy Traffic: {url} | Severity: {threat_feed[bad_domain]}\n")

    report.close()

threat_feed = load_threat_feed("logs/threat_feed.txt")
counts = analyze_dns_logs("logs/dns.log", threat_feed)
urls = analyze_proxy_logs("logs/proxy.log", threat_feed)
write_report("report.txt", counts, urls, threat_feed)