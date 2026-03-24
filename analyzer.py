from collections import Counter

#accessing the dns and proxy logs files
dns_file = open("logs/dns.log", "r")
proxy_file = open("logs/proxy.log", "r")

# -----------------------------------------------
# Analyzing the DNS logs for malicious domains
# -----------------------------------------------

# stores the domains
domains = []

for line in dns_file:
    # used to split lines in dns file
    parts = line.split()

    # gets the domain using parts variable to split specific parts of the list
    dns_domain = parts[3].split("=")[1]
    
    #adds the found domain to domains list
    domains.append(dns_domain)

# closes dns file and counts domains
dns_file.close()
counts = Counter(domains)

#------------------------------------
# stores the domains to watch out for
threat_feed = {}

# Reads the threat file with bad domains
threat_file = open("logs/threat_feed.txt", "r")

for line in threat_file:
    line = line.strip()

    if line:
        parts = line.split(',')
        threat_domain = parts[0]
        severity = parts[1]
        threat_feed[threat_domain] = severity

threat_file.close()
#-------------------------------------

for domain, count in counts.items():
    print(domain,":", count)

found_suspicious = False

for domain, count in counts.items():

    if domain in threat_feed:
        print("ALERT: Suspicious domain detected:", domain, "| Severity:", threat_feed[domain])
        found_suspicious = True

    if count > 3:
        print("ALERT: Possible DNS beaconing:", domain)

if not found_suspicious:
    print("No suspicious domains found.\n")

# -----------------------------------------------
# Analyzing the proxy logs to detect malicious traffic
# -----------------------------------------------

print("\nNow analyzing Proxy Logs...")
print("Logs Accessed:")

# stores the urls from the proxy logs
urls= []

for line in proxy_file:
    parts = line.split()

    url = parts[3].split("=")[1]
    urls.append(url)
    print("URL Accessed:", url)

proxy_file.close()

print("\nLooking for malicious traffic:")

for url in urls:
    for bad_domain in threat_feed:
        if bad_domain in url:
            print("ALERT: Malicious proxy traffic:", url, "| Severity:", threat_feed[bad_domain])

# -------------------------------------------
# Writing dns and proxy findings to the report
#--------------------------------------------
report = open("report.txt", "w")
report.write("------------------------\n")
report.write("Security Analysis Report\n")
report.write("------------------------\n")

# Wrtiting dns findings
report.write("DNS:\n")
report.write("------------------\n")
for domain, count in counts.items():
    if domain in threat_feed:
        report.write(f"Suspicious DNS Query: {domain} | Severity: {threat_feed[domain]}\n")


# Writing proxy findings
report.write("\nProxy:\n")
report.write("------------------\n")
for url in urls:
    for bad_url in threat_feed:
        if bad_url in url:
            report.write(f"Malicious Proxy Traffic: {url} | Severity: {threat_feed[bad_url]}\n")
report.close